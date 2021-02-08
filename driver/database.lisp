;;;; database.lisp
;;;;
;;;; This file is part of the MONGO-CL-DRIVER library, released under Lisp-LGPL.
;;;; See file COPYING for details.
;;;;
;;;; Author: Moskvitin Andrey <archimag@gmail.com>

(in-package #:mongo-cl-driver)

(defgeneric mongo-client (obj)
  (:documentation "Get MongoClient associated with OBJ"))

(defclass database ()
  ((mongo-client :initform nil :initarg :mongo-client :reader mongo-client)
   (name :initarg :name :reader database-name)))

(defmethod write-concern ((db database))
  (write-concern (mongo-client db)))

(defmethod print-object ((db database) stream)
  (print-unreadable-object (db stream :type t :identity t)
    (princ (database-name db) stream)))

;;;; commands

(defun run-command (db cmd)
  (try-unpromisify
   (alet ((reply (send-message-and-read-reply
                  (mongo-client db)
                  (make-instance 'op-query
                                 :number-to-return 1
                                 :full-collection-name (format nil "~A.$cmd" (database-name db))
                                 :query (if (stringp cmd) ($ cmd t) cmd)))))
     (first (op-reply-documents reply)))))

;;;; errors

(defun last-error (db)
  (run-command db "getLastError"))

(defun previous-error (db)
  (run-command db "getPrevError"))

(defun reset-error (db)
  (run-command db "resetError"))

;;;; auth

(defun authenticate-mongo-cr (database username password)
  (labels ((md5 (text)
             (ironclad:byte-array-to-hex-string
              (ironclad:digest-sequence
               :md5 (babel:string-to-octets text :encoding :utf-8))))
           (nonce-key (nonce username password)
             (format nil
                     "~A~A~A"
                     nonce
                     username
                     (md5 (format nil "~A:mongo:~A" username password)))))
    (try-unpromisify
     (alet ((nonce-reply (run-command database "getnonce")))
       (run-command database
                    ($ "authenticate" 1
                       "user" username
                       "nonce" (gethash "nonce" nonce-reply)
                       "key" (nonce-key (gethash "nonce" nonce-reply) username password)))))))

(defun password-digest (username password)
  (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :md5 (ironclad:ascii-string-to-byte-array (concatenate 'string username ":mongo:" password)))))

(defun authenticate-scram (database username password)
  (declare (optimize debug))
  (labels ((payload (s)
             (make-instance 'mongo-cl-driver.bson:binary-data
                            :octets (ironclad:ascii-string-to-byte-array s)))
           (run (&rest args)
               (let ((doc (run-command database (apply #'$ args))))
                 (when (= (truncate (gethash "ok" doc)) 0)
                   (error (gethash "errmsg" doc)))
                 doc))
           (get-payload (doc)
             (babel:octets-to-string (mongo-cl-driver.bson:binary-data-octets (gethash "payload" doc))))
           (challenge (payload prev-response)
             (run "saslContinue" 1
                  "conversationId" (gethash "conversationId" prev-response)
                  "payload" (payload payload))))
    (let* ((nonce (cl-scram:gen-client-nonce))
           (initial-message (cl-scram:gen-client-initial-message :username username :nonce nonce))
           (initial-response-doc (run "saslStart" 1
                                      "mechanism" "SCRAM-SHA-1"
                                      "payload" (payload initial-message)
                                      "autoAuthorize" 1))
           (initial-response (get-payload initial-response-doc)))
      ;; (format t "nonce: ~a~%" nonce)
      ;; (format t "initial-message: ~a~%" initial-message)
      ;; (format t "initial-response-doc: ~a~%" (hash-table-alist initial-response-doc))
      ;; (format t "initial-response: ~a~%" initial-response)
      (unless (>= (cl-scram:parse-server-iterations :response initial-response) 4096)
        (error "Server returned an invalid iteration count"))
      (let* ((final-message (cl-scram:gen-client-final-message
                             :password (password-digest username password)
                             :client-nonce nonce
                             :client-initial-message initial-message
                             :server-response initial-response))
             (final-response-doc (challenge (cdr (assoc 'cl-scram::final-message final-message))
                                            initial-response-doc))
             (final-response (get-payload final-response-doc))
             ;; From Python driver: Depending on how it's configured, Cyrus SASL (which the server uses)
             ;; requires a third empty challenge.
             (complete (or (gethash "done" final-response-doc)
                           (gethash "done" (challenge "" final-response-doc)))))
        ;; (format t "final-message: ~a~%" final-message)
        ;; (format t "final-response-doc: ~a~%" (hash-table-alist final-response-doc))
        (unless complete
          (error "SASL conversation failed to complete"))
        (unless (and (string= "v=" final-response :end2 2)
                     (string= (cdr (assoc 'cl-scram::server-signature final-message))
                              final-response :start2 2))
          (error "Invalid server signature"))))))

(defun authenticate (database username password)
  (let ((max-wire-version (gethash "maxWireVersion"
                                   (mongo-cl-driver:run-command database "ismaster"))))
    (if (>= max-wire-version 3)
        (authenticate-scram database username password)
        (authenticate-mongo-cr database username password))))

(defun logout (database)
  (run-command database "logout"))

;;;; collections

(defun collection-names (database)
  "Get a list of all the collection in this DATABASE."
  (try-unpromisify
   (alet ((reply (send-message-and-read-reply
                  (mongo-client database)
                  (make-instance 'op-query
                                 :full-collection-name (format nil "~A.system.namespaces" (database-name database))
                                 :query ($)))))
     (iter (for item in (op-reply-documents reply))
           (let* ((fullname (gethash "name" item))
                  (name (second (multiple-value-list (starts-with-subseq (format nil "~A." (database-name database))
                                                                         fullname
                                                                         :return-suffix t)))))
             (when (and name (not (cl:find #\$ name)))
               (collect name)))))))

(defun create-collection (db name &key size capped max)
  (check-type name string)
  "Create new Collection in DATABASE."
  (let ((cmd ($ "create" name)))
    (iter (for (key . value) in `(("size" . ,size) ("cappend" . ,capped) ("max" . ,max)))
          (setf (gethash key cmd) value))
    (run-command db cmd)))

(defun drop-collection (db name)
  (run-command db ($ "drop" name)))

;; (defun rename-collection (db name &key drop-target)
;;   )

;;;; eval

(defun eval-js (db code &key args nolock)
  (let ((cmd ($ "$eval" (make-instance 'mongo.bson:javascript :code code))))
    (when args
      (setf (gethash "args" cmd) args))
    (when nolock
      (setf (gethash "nolock" cmd) t))
    (try-unpromisify
     (alet ((retval (run-command db cmd)))
       (gethash "retval" retval)))))

;;;; misc

(defun stats (db)
  (run-command db "dbStats"))

(defun cursor-info (db)
  (run-command db "cursorInfo"))


;; TODO
;; 
;; renameCollection
;; dereference
;;
;; admin
;; addUser
;; removeUser

