;;;; indexes.lisp
;;;;
;;;; This file is part of the MONGO-CL-DRIVER library, released under Lisp-LGPL.
;;;; See file COPYING for details.
;;;;
;;;; Author: Moskvitin Andrey <archimag@gmail.com>

(in-package #:mongo-cl-driver)

(defun make-name (keys)
  (format nil "~{~A_~A~^_~}"
          (if (typep keys 'hash-table)
              (hash-table-plist keys)
              (alist-plist keys))))

(defun index-collection (collection)
  (collection (collection-database collection)
              "system.indexes"))

;; (defun create-index (collection keys &optional (options ($)))
;;   (let ((index (copy-hash-table options))
;;         (index-collection (index-collection collection))
;;         (name (make-name keys)))
;;     (setf (gethash "key" index) keys
;;           (gethash "ns" index) (fullname collection)
;;           (gethash "name" index) (gethash "name" index name))
;;     (pushnew name (collection-indexes collection) :test #'equal)
;;     (insert index-collection index)))

(defun create-index (collection keys &optional (options ($)))
  (let ((index (copy-hash-table options)))
    (setf (gethash "key" index)
          (if (typep keys 'hash-table)
              keys
              (mongo-cl-driver.bson:make-document-alist :elements keys)))
    (setf (gethash "name" index) (gethash "name" index (make-name keys)))
    (let ((cmd ($ "createIndexes" (fullname collection)
                  "indexes" (list index))))
      (try-unpromisify
       (alet ((reply (run-command (collection-database collection) cmd)))
         (case (truncate (gethash "ok" reply))
           (0 (values nil (gethash "errmsg" reply)))
           (1 t)))))))

(defun ensure-index (collection keys &optional (options ($)))
  (create-index collection keys options))

(defun drop-indexes (collection &optional (name "*"))
  (setf (collection-indexes collection) nil)
  (let ((cmd ($ "dropIndexes" (fullname collection)
                "index" name)))
    (try-unpromisify
     (alet ((reply (run-command (collection-database collection) cmd)))
       (case (truncate (gethash "ok" reply))
         (0 (values nil (gethash "errmsg" reply)))
         (1 t))))))

(defun reindex (collection)
  (let ((cmd ($ "reIndex" (collection-name collection))))
    (try-unpromisify
     (alet ((reply (run-command (collection-database collection) cmd)))
       reply))))

(defun index-information (collection name)
  (find-one (index-collection collection)
            :query ($ "ns" (fullname collection)
                      "name" name)))

(defun indexes (collection)
  (let ((cmd ($ "listIndexes" (fullname collection))))
    (try-unpromisify
     (alet ((reply (run-command (collection-database collection) cmd)))
       reply))))
