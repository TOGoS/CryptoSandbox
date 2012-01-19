<?php

function der2pem($der_data) {
  $pem = chunk_split(base64_encode($der_data), 64, "\n");
  $pem = "-----BEGIN PUBLIC KEY-----\n".$pem."-----END PUBLIC KEY-----\n";
  return $pem;
}

$content = file_get_contents("sandbox/content");
$sigData = file_get_contents("sandbox/signature-data");
$prvKeyEnc = file_get_contents("sandbox/private-key");
$pubKeyEnc = file_get_contents("sandbox/public-key");

$pubKeyPem = der2pem($pubKeyEnc);

$pubKey = openssl_get_publickey($pubKeyPem);
if( $pubKey === false ) {
	echo "Failed to load public key.\n";
	exit(1);
}

// echo "Key details: ";
// print_r( openssl_pkey_get_details($pubKey) ); 

//echo "Public key PEM: $pubKeyPem\n";

//echo "X.509 parsed: ";
//print_r( openssl_x509_parse($pubKeyEnc) );

$verified = openssl_verify( $content, $sigData, $pubKey );

echo $verified ? "Verified!" : "Did not verify!", "\n";
