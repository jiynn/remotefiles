<?php
header('Content-Type: application/json');

$hashedKeys = [
    '$2y$10$lyh7tCgDKaDLQJuY9ZXnSeMbxWRO7kflQ6NTmYnsWaSgkWgrvs0OS',
    '$2y$10$7LK62jWplzObhgljJKTWv.pLTol48/iQYpzkfT9sTb9f3R08oUT.a',
    '$2y$10$QZHNMKLJIhGFEDCBA9876uXWVUTSRQPONMLKJIHGFEDCBA98765'
];

echo json_encode($hashedKeys);
