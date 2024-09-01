<?php
header('Content-Type: application/json');

$hashedKeys = [
    '$2y$10$1234567890abcdefghijk.uvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '$2y$10$abcdefghijk1234567890.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
    '$2y$10$uvwxyzABCDEFGHIJKLMNOP.QRSTUVWXYZ0123456789abcdefghijk'
];

echo json_encode($hashedKeys);
