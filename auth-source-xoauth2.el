;;; auth-source-xoauth2.el --- Integrate auth-source with XOAUTH2

;; Copyright 2018 Google LLC
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;    http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

;; Author: Cesar Crusius <ccrusius@google.com>
;; Version: 1.0.0
;; Package-Requires: ((emacs "24.4"))
;; Created: 06 Jan 2018
;; Keywords: gmail xoauth2 auth-source username password login

;; This file is not part of GNU Emacs.

;; This package is not an official Google product.

;;; Commentary:

;; Adds XOAuth2 authentication capabilities to auth-source.

;; Some code is basically the same as code in the external
;; `request.el' and `oauth2.el' packages.

;;; Code:

(require 'auth-source)
(require 'cl-lib)
(require 'json)
(require 'seq)
(require 'subr-x)
(require 'auth-source-pass)

;;; Auth source interface and functions

(defvar auth-source-xoauth2-creds nil
  "A property list containing values for the following XOAuth2 keys:
:token-url, :client-id, :client-secret, and :refresh-token.

If this is set to a string, it is considered the name of a file
containing one sexp that evaluates to the property list above.  If
this is set to a function, it will be called with HOST, USER, and PORT
values, and should return the respective property list.

This package provides a function that retrieves the values from a
password-store.  See `auth-source-xoauth2-pass-creds' for details.

If you are using this to authenticate to Google, the values can be
obtained through the following procedure (note that Google changes
this procedure somewhat frequently, so the steps may be slightly
different):

1. Go to the developer console, https://console.developers.google.com/project
2. Create a new project (if necessary), and select it once created.
3. Select \"APIs & Services\" from the navigation menu.
4. Select \"Credentials\".
5. Create new credentials of type \"OAuth Client ID\".
6. Choose application type \"Other\".
7. Choose a name for the client.

This should get you all the values but for the refresh token.  For that one:

1. Clone the https://github.com/google/gmail-oauth2-tools repository
2. Execute the following command in the cloned repository:

   python2.7 python/oauth2.py
     --generate_oauth2_token \
     --client_id=<client id from previous steps> \
     --client_secret=<client secret from previous steps>

You should now have all the required values (the :token-url value should
be \"https://accounts.google.com/o/oauth2/token\").")

(cl-defun auth-source-xoauth2-search (&rest spec
                                            &key backend type host user port
                                            &allow-other-keys)
  "Given a property list SPEC, return search matches from the :backend.
See `auth-source-search' for details on SPEC."
  ;; just in case, check that the type is correct (null or same as the backend)
  (cl-assert (or (null type) (eq type (oref backend type)))
             t "Invalid XOAuth2 search: %s %s")
  (let ((hosts (if (and host (listp host)) host `(,host)))
        (ports (if (and port (listp port)) port `(,port))))
    (catch 'match
      (dolist (host hosts)
        (dolist (port ports)
          (let ((match (auth-source-xoauth2--search
                        spec type host user port)))
            (when match
              (throw 'match `(,match)))))))))

(cl-defun auth-source-xoauth2--search (spec type host user port)
  "Given a property list SPEC, return search matches from the :backend.
See `auth-source-search' for details on SPEC."
  (when-let ((token
              (cond
               ((functionp auth-source-xoauth2-creds)
                (funcall auth-source-xoauth2-creds host user port))
               ((stringp auth-source-xoauth2-creds)
                (auth-source-xoauth2--file-creds))
               (t auth-source-xoauth2-creds))))
    (when-let ((token-url (plist-get token :token-url))
               (client-id (plist-get token :client-id))
               (client-secret (plist-get token :client-secret))
               (refresh-token (plist-get token :refresh-token)))
      (when-let (secret (cdr (assoc 'access_token
                                    (auth-source-xoauth2--url-post
                                     token-url
                                     (concat "client_id=" client-id
                                             "&client_secret=" client-secret
                                             "&refresh_token=" refresh-token
                                             "&grant_type=refresh_token")))))
        (list :host host :port port :user user :secret secret)))))

(defun auth-source-xoauth2--url-post (url data)
  "Post DATA to the given URL, and return the JSON-parsed reply."
  (let ((url-request-method "POST")
        (url-request-data data)
        (url-request-extra-headers
         '(("Content-Type" . "application/x-www-form-urlencoded"))))
    (with-current-buffer (url-retrieve-synchronously url)
      (goto-char (point-min))
      (when (search-forward-regexp "^$" nil t)
        (let ((data (json-read)))
          (kill-buffer (current-buffer))
          data)))))

;;;###autoload
(defun auth-source-xoauth2-enable ()
  "Enable auth-source-xoauth2."
  (add-to-list 'auth-sources 'xoauth2)
  ;; Add functionality to nnimap-login
  (advice-add 'nnimap-login :around
              (lambda (fn user password)
                (if (and (eq nnimap-authenticator 'xoauth2)
                         (nnimap-capability "AUTH=XOAUTH2")
                         (nnimap-capability "SASL-IR"))
                    (nnimap-command
                     (concat "AUTHENTICATE XOAUTH2 "
                             (base64-encode-string
                              (concat "user=" user "\1auth=Bearer " password "\1\1")
                              t)))
                  (funcall fn user password))))
  ;; Add the functionality to smtpmail-try-auth-method
  (cond
   ((>= emacs-major-version 27)
    (cl-defmethod smtpmail-try-auth-method
      (process (_mech (eql xoauth2)) user password)
      (smtpmail--try-auth-xoauth2-method process user password)))
   (t
    (advice-add 'smtpmail-try-auth-method :around
                (lambda (fn process mech user password)
                  (if (eq mech 'xoauth2)
                      (smtpmail--try-auth-xoauth2-method process user password)
                    (funcall fn process mech user password)))))))

(defvar auth-source-xoauth2-backend
  (auth-source-backend
   (format "xoauth2")
   :source "." ;; not used
   :type 'xoauth2
   :search-function #'auth-source-xoauth2-search)
  "XOAuth2 backend for password-store.")

(defun auth-source-xoauth2-backend-parse (entry)
  "Create a XOAuth2 auth-source backend from ENTRY."
  (when (eq entry 'xoauth2)
    (auth-source-backend-parse-parameters entry auth-source-xoauth2-backend)))

(advice-add 'auth-source-backend-parse :before-until #'auth-source-xoauth2-backend-parse)
;;(add-hook 'auth-source-backend-parser-functions #'auth-source-xoauth2-backend-parse)

;;; File sub-backend

(defun auth-source-xoauth2--file-creds ()
  "Load the file specified by `auth-source-xoauth2-creds`."
  (when (not (string= "gpg" (file-name-extension auth-source-xoauth2-creds)))
    (error "The auth-source-xoauth2-creds file must be GPG encrypted"))
  (eval (with-temp-buffer
          (insert-file-contents auth-source-xoauth2-creds)
          (goto-char (point-min))
          (read (current-buffer)))
        (buffer-string)))

;;; Password-store sub-backend

(defun auth-source-xoauth2-pass--find-match (host user port)
  "Find password for given HOST, USER, and PORT.
This is a wrapper around `auth-pass--find-match`, which is needed
because the MELPA and Emacs 26.1 versions of the function accept
a different number of arguments."
  (cond
   ((>= emacs-major-version 27) (auth-source-pass--find-match host user port))
   ((>= emacs-major-version 26) (auth-source-pass--find-match host user))
   (t (auth-source-pass--find-match host user port))))

(cl-defun smtpmail--try-auth-xoauth2-method (process user password)
  "Authenticate to SMTP PROCESS with USER and PASSWORD via XOAuth2."
  (smtpmail-command-or-throw
   process
   (concat "AUTH XOAUTH2 "
           (base64-encode-string
            (concat "user=" user "\1auth=Bearer " password "\1\1")
            t))
   235))

(defun auth-source-xoauth2--pass-get (key entry)
  "Retrieve KEY from password-store ENTRY."
  (let ((ret (auth-source-pass-get key entry)))
    (or ret (message "Missing XOAuth2 entry value for '%s'" key))
    ret))

(defun auth-source-xoauth2-pass-creds (host user port)
  "Retrieve a XOAUTH2 access token using `auth-source-pass'.
This function retrieve a password-store entry matching HOST, USER, and
PORT. This entry should contain the following key-value pairs:

xoauth2_token_url: <value>
xoauth2_client_id: <value>
xoauth2_client_secret: <value>
xoauth2_refresh_token: <value>

which are used to build and return the property list required by
`auth-source-xoauth2-creds'."
  (when-let ((entry (auth-source-xoauth2-pass--find-match host user port)))
    (when-let
        ((url (auth-source-xoauth2--pass-get "xoauth2_token_url" entry))
         (id (auth-source-xoauth2--pass-get "xoauth2_client_id" entry))
         (secret (auth-source-xoauth2--pass-get "xoauth2_client_secret" entry))
         (token (auth-source-xoauth2--pass-get "xoauth2_refresh_token" entry)))
      (list
       :token-url url
       :client-id id
       :client-secret secret
       :refresh-token token))))

(provide 'auth-source-xoauth2)
;;; auth-source-xoauth2.el ends here
