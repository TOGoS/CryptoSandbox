<?php

function derToPem($der) {
	$pem = chunk_split(base64_encode($der), 64, "\n");
	$pem = "-----BEGIN PUBLIC KEY-----\n".$pem."-----END PUBLIC KEY-----\n";
	return $pem;
}

function pemToDer($pem) {
	if( !preg_match('#--+BEGIN PUBLIC KEY--+\n(.*)\n--+END PUBLIC KEY--+#s', $pem, $bif) ) {
		throw new Exception("Failed to parse PEM data: $pem");
	}
	$base64 = $bif[1];
	return base64_decode($base64);
}
