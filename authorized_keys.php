<?php
header('Content-Type: application/json');

$authorized_keys = [
    'ResumeSite' => 'e8cb81a885497b144a6193ca82dabca6dc4f2db44de3bda29fda0173699fbd85',
    // Add more organizations and their hashed keys as needed
];

echo json_encode($authorized_keys);
