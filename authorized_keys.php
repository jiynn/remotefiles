<?php
header('Content-Type: application/json');

$authorized_keys = [
    'ResumeSite Demo' => hash('sha256', 'e8cb81a885497b144a6193ca82dabca6dc4f2db44de3bda29fda0173699fbd85'),
    'Organization2' => hash('sha256', 'LEAD-IV-DEPLOYMENT-KEY-2024'),
    'Organization3' => hash('sha256', 'LEAD-IV-DEPLOYMENT-KEY-2025'),
];

echo json_encode($authorized_keys);
