<?php

$cases = [
	[
	 'name' => 'PHP Public Key',
	 'type' => 'public key',
	 'bits' => 2048,
	 'file' => 'temp/php-pubkey',
	]
];

function sys($cmd) {
	system($cmd, $stat);
	if( $stat !== 0 ) {
		fwrite(STDERR, "Command failed with code $stat: $cmd\n");
	}
}

foreach( $cases as $case ) {
	sys("make {$case['file']}");
	$inspected = `./inspect {$case['file']}`;
	
	echo "<p>", htmlspecialchars("{$case['name']} ({$case['bits']}-bit key)"), "</p>\n\n";
	echo "<pre>", htmlspecialchars($inspected), "</pre>\n";
}
