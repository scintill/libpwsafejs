<?php

$fd = fopen('ECB_VT.TXT', 'r');
$tests = array();

$highI = 0;
$totalTests = 0;

while(!feof($fd)) {
    $line = fgets($fd);
    if (strpos($line, 'KEY=') === 0) {
        $key = substr(trim($line), 4);
    } else if (strpos($line, 'I=') === 0) {
        $i = (int)substr($line, 2);
        if ($i < $highI) {
            $totalTests += $highI;
        }
        $highI = $i;

        $line = trim(fgets($fd));
        $pt = substr($line, 3);
        $line = trim(fgets($fd));
        $ct = substr($line, 3);
        $tests[$key][] = array('pt' => $pt, 'ct' => $ct);
    }
}

$totalTests += $highI;

$t = 0;
foreach ($tests as $key => $subTests) {
    $t += count($subTests);
}
if ($t != $totalTests) {
    echo 'Incorrect count of tests: got ', $t, ', expecting ', $totalTests, "\n";
    die;
}

echo str_replace(',{', ",\n{", json_encode($tests));
