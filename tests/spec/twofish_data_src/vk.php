<?php

$fd = fopen('ECB_VK.TXT', 'r');
$tests = array();

$highI = 0;
$totalTests = 0;

while(!feof($fd)) {
    $line = fgets($fd);
    if (strpos($line, 'I=') === 0) {
        $i = (int)substr($line, 2);
        if ($i < $highI) {
            $totalTests += $highI;
        }
        $highI = $i;

        $line = trim(fgets($fd));
        $key = substr($line, 4);
        $line = trim(fgets($fd));
        $ct = substr($line, 3);
        $tests[] = array('ct' => $ct, 'key' => $key);
    }
}

$totalTests += $highI;
if (sizeof($tests) != $totalTests) {
    echo 'Incorrect count of tests: got ', sizeof($tests), ', expecting ', $totalTests, "\n";
    die;
}

echo str_replace(',{', ",\n{", json_encode($tests));
