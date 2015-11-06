defalt: pk-structure-report.html

.PHONY: \
	default \
	generated-keys

.DELETE_ON_ERROR: # Yes plz

generated-keys/php/public-key:
	mkdir -p generated-keys/php
	php php-src/generate-pubkey.php >"$@"

generated-keys/php: generated-keys/php/public-key

generated-keys/java: java-src/togos/cryptosandbox/RSAKeyGenerator.java
	javac -d bin java-src/togos/cryptosandbox/RSAKeyGenerator.java
	java -cp bin togos.cryptosandbox.RSAKeyGenerator
	touch "$@"

generated-keys: \
	generated-keys/java \
	generated-keys/php

pk-structure-report.html: make-pk-structure-report.php php-src generated-keys
	php make-pk-structure-report.php >"$@"
