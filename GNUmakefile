PKG := auth-source-xoauth2

EMACS_INIT := --eval "(progn \
(require 'package) \
(push '(\"melpa\" . \"https://melpa.org/packages/\") package-archives) \
(package-initialize) \
(unless package-archive-contents (package-refresh-contents)) \
(unless (package-installed-p 'package-lint) (package-install 'package-lint)) \
(require 'package-lint) \
)"

EMACS := emacs -batch $(EMACS_INIT)

$(PKG).elc: $(PKG).el
	emacs --no-init-file --no-site-file --batch --eval '(byte-compile-file "$<")'

checkdoc:
	$(EMACS) --eval "(checkdoc-file \"auth-source-xoauth2.el\")"

lint:
	$(EMACS) -f package-lint-batch-and-exit auth-source-xoauth2.el
