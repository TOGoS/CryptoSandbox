<?php

require __DIR__.'/util.php';

$keyPair = openssl_pkey_new( array(
	'digest_alg' => 'sha1',
	'private_key_bits' => 2048, // For faster unit testing
	'private_key_type' => OPENSSL_KEYTYPE_RSA
) );
		
$det = openssl_pkey_get_details($keyPair);

/** PEM-formatted public key */
$pubKeyPem = $det['key'];
$pubKeyDer = pemToDer($pubKeyPem);
echo $pubKeyDer;
