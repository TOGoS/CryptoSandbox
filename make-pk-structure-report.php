<?php

$cases = [
	[
	 'name' => 'PHP Public Key',
	 'type' => 'public key',
	 'bits' => 2048,
	 'file' => 'generated-keys/php/public-key',
	],
	[
	 'name' => 'Java Public Key',
	 'type' => 'public key',
	 'bits' => 2048,
	 'file' => 'generated-keys/java/public-key',
	],
	[
	 'name' => 'Java Private Key',
	 'type' => 'private key',
	 'bits' => 2048,
	 'file' => 'generated-keys/java/private-key',
	]
];

function sys($cmd) {
	system($cmd, $stat);
	if( $stat !== 0 ) {
		fwrite(STDERR, "Command failed with code $stat: $cmd\n");
	}
}

function htmltext($text) {
	return str_replace('&quot;','"',htmlspecialchars($text));
}

foreach( $cases as $case ) {
	#sys("make {$case['file']}");
	$inspected = `./inspect {$case['file']}`;
	
	echo "<p>", htmlspecialchars("{$case['name']} ({$case['bits']}-bit {$case['type']})"), "</p>\n\n";
	$class = str_replace(' ','-',$case['type']);
	echo "<blockquote class=\"{$class}\"><pre><code>", htmltext($inspected), "</code></pre></blockquote>\n\n";
}
