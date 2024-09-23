<?php
function isValidDeployment() {
    $localKeyPath = __DIR__ . '/includes/deployment_key.txt';
        
    if (!file_exists($localKeyPath)) {
        die("Deployment key file not found. Program locked.");
    }
    
    $localKey = trim(file_get_contents($localKeyPath));
    
    $remoteKeysUrl = 'https://tinyurl.com/24sj4ckr';
    $remoteKeys = @file_get_contents($remoteKeysUrl);
    if ($remoteKeys === false) {
        die("Unable to fetch remote keys. Program locked.");
    }

    $keyList = json_decode($remoteKeys, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        die("Invalid remote key data. JSON error: " . json_last_error_msg());
    }

    foreach ($keyList as $hashedKey) {
        if (password_verify($localKey, $hashedKey)) {
            return true;
        }
    }

    die("Invalid deployment. Program locked.");
}

function authenticate_user($conn, $username, $password) {
    $query = "SELECT * FROM users WHERE username = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($result);
    
    if ($user && password_verify($password, $user['password'])) {
        return $user;
    }
    return false;
}

function change_user_password($conn, $user_id, $new_password) {
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    $query = "UPDATE users SET password = ? WHERE id = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "si", $hashed_password, $user_id);
    return mysqli_stmt_execute($stmt);
}

function get_all_users($conn) {
    $query = "SELECT * FROM users";
    $result = mysqli_query($conn, $query);
    if (!$result) {
        error_log("Query failed: " . mysqli_error($conn));
        return [];
    }
    $users = mysqli_fetch_all($result, MYSQLI_ASSOC);
    if (!$users) {
        error_log("No users found or error fetching users");
        return [];
    }
    return $users;
}

function get_all_tables($conn) {
    $query = "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()";
    $result = mysqli_query($conn, $query);
    $tables = [];
    while ($row = mysqli_fetch_row($result)) {
        $tables[] = $row[0];
    }
    return $tables;
}

function get_table_fields($conn, $table) {
    $fields = [];
    $query = "SHOW COLUMNS FROM `$table`";
    $result = mysqli_query($conn, $query);
    
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $fields[] = $row['Field'];
        }
        mysqli_free_result($result);
    }
    
    return $fields;
}

function checkDbConfigIntegrity() {
    $dbConfigPath = __DIR__ . '/config/db_config.php';
    $dbConfigContent = file_get_contents($dbConfigPath);
    
    if (strpos($dbConfigContent, 'isValidDeployment();') === false) {
        die("Unauthorized modification detected. Program locked.");
    }
}

// Call the function to check db_config.php integrity
checkDbConfigIntegrity();

function update_user_lead_assignment($conn, $user_id, $assignments) {
    mysqli_query($conn, "DELETE FROM user_table_assignments WHERE user_id = $user_id");
    
    foreach ($assignments as $assignment) {
        $table = mysqli_real_escape_string($conn, $assignment['table']);
        $limit = intval($assignment['limit']);
        $zips = mysqli_real_escape_string($conn, $assignment['zip_codes']);
        $query = "INSERT INTO user_table_assignments (user_id, assigned_table, lead_limit, zip_codes) 
                  VALUES ($user_id, '$table', $limit, '$zips')";
        mysqli_query($conn, $query);
    }
    
    return true;
}

function clear_user_leads($conn, $user_id, $assigned_table) {
    $query = "UPDATE `$assigned_table` SET assigned_to = NULL WHERE assigned_to = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "i", $user_id);
    return mysqli_stmt_execute($stmt);
}

function create_user($conn, $username, $password, $is_admin) {
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $query = "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ssi", $username, $hashed_password, $is_admin);
    return mysqli_stmt_execute($stmt);
}

function delete_user($conn, $user_id) {
    $query = "DELETE FROM users WHERE id = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "i", $user_id);
    return mysqli_stmt_execute($stmt);
}

function get_lead_assignment_stats($conn, $users) {
    $stats = [];
    foreach ($users as $user) {
        $assignments = mysqli_query($conn, "SELECT * FROM user_table_assignments WHERE user_id = {$user['id']}");
        $user_stats = [];
        while ($assignment = mysqli_fetch_assoc($assignments)) {
            $count_query = "SELECT COUNT(*) as count FROM `{$assignment['assigned_table']}` WHERE assigned_to = {$user['id']}";
            if (!empty($assignment['zip_codes'])) {
                $zips = explode(',', $assignment['zip_codes']);
                $zip_placeholders = implode(',', array_fill(0, count($zips), '?'));
                $count_query .= " AND zip IN ($zip_placeholders)";
            }
            $count_stmt = mysqli_prepare($conn, $count_query);
            if (!empty($assignment['zip_codes'])) {
                $types = str_repeat('s', count($zips));
                mysqli_stmt_bind_param($count_stmt, $types, ...$zips);
            }
            mysqli_stmt_execute($count_stmt);
            $result = mysqli_stmt_get_result($count_stmt);
            $count = mysqli_fetch_assoc($result)['count'];
            $user_stats[] = [
                'table' => $assignment['assigned_table'],
                'limit' => $assignment['lead_limit'],
                'assigned' => $count,
                'zip_codes' => $assignment['zip_codes']
            ];
        }
        $stats[] = [
            'username' => $user['username'],
            'assignments' => $user_stats
        ];
    }
    return $stats;
}

function assign_leads($conn, $stats) {
    $assigned_count = 0;
    $errors = [];
    $batch_size = 1000; // Adjust this value based on your system's performance

    foreach ($stats as $user_stat) {
        $user_id = $user_stat['user_id'];
        foreach ($user_stat['assignments'] as $assignment) {
            $table = $assignment['table'];
            $limit = $assignment['limit'];
            $assigned = $assignment['assigned'];
            $zip_codes = explode(',', $assignment['zip_codes']);

            $to_assign = max(0, $limit - $assigned);
            $total_leads = get_unassigned_lead_count($conn, $table, $zip_codes);

            while ($to_assign > 0 && $total_leads > 0) {
                $batch_limit = min($batch_size, $to_assign);
                $random_indices = array_rand(range(0, $total_leads - 1), $batch_limit);
                
                if (!is_array($random_indices)) {
                    $random_indices = [$random_indices];
                }

                $placeholders = implode(',', $random_indices);
                $select_query = "SELECT lead_id FROM (
                    SELECT lead_id, @row := @row + 1 AS row_num
                    FROM $table, (SELECT @row := 0) AS r
                    WHERE assigned_to IS NULL
                    " . (!empty($zip_codes) ? "AND zip_code IN (" . implode(',', array_fill(0, count($zip_codes), '?')) . ")" : "") . "
                ) AS numbered
                WHERE row_num IN ($placeholders)";

                $stmt = mysqli_prepare($conn, $select_query);
                if (!empty($zip_codes)) {
                    $types = str_repeat('s', count($zip_codes));
                    mysqli_stmt_bind_param($stmt, $types, ...$zip_codes);
                }
                mysqli_stmt_execute($stmt);
                $result = mysqli_stmt_get_result($stmt);

                $lead_ids = [];
                while ($lead = mysqli_fetch_assoc($result)) {
                    $lead_ids[] = $lead['lead_id'];
                }

                if (!empty($lead_ids)) {
                    $update_query = "UPDATE $table SET assigned_to = ? WHERE lead_id IN (" . implode(',', $lead_ids) . ")";
                    $stmt = mysqli_prepare($conn, $update_query);
                    mysqli_stmt_bind_param($stmt, "i", $user_id);
                    if (mysqli_stmt_execute($stmt)) {
                        $assigned_count += count($lead_ids);
                        $to_assign -= count($lead_ids);
                    } else {
                        $errors[] = "Error assigning leads to user {$user_id}";
                    }
                }

                $total_leads -= $batch_limit;
            }
        }
    }

    return [
        'success' => true,
        'message' => "Assigned $assigned_count leads successfully." . (count($errors) > 0 ? " Errors: " . implode(", ", $errors) : ""),
    ];
}

function get_unassigned_lead_count($conn, $table, $zip_codes) {
    $query = "SELECT COUNT(*) as total FROM $table WHERE assigned_to IS NULL";
    if (!empty($zip_codes)) {
        $zip_placeholders = implode(',', array_fill(0, count($zip_codes), '?'));
        $query .= " AND zip_code IN ($zip_placeholders)";
    }
    $stmt = mysqli_prepare($conn, $query);
    if (!empty($zip_codes)) {
        $types = str_repeat('s', count($zip_codes));
        mysqli_stmt_bind_param($stmt, $types, ...$zip_codes);
    }
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);
    return $row['total'];
}


function clear_leads($conn) {
    $users = get_all_users($conn);
    $cleared_count = 0;

    foreach ($users as $user) {
        $assignments = get_user_assignments($conn, $user['id']);
        foreach ($assignments as $assignment) {
            $table = $assignment['assigned_table'];
            $limit = $assignment['lead_limit'];
            $current_assigned = get_assigned_lead_count($conn, $user['id'], $table);

            if ($current_assigned > $limit) {
                $to_clear = $current_assigned - $limit;
                $cleared = clear_random_user_leads($conn, $user['id'], $table, $to_clear);
                $cleared_count += $cleared;
            }
        }
    }

    return [
        'message' => "Cleared $cleared_count leads.",
        'cleared' => $cleared_count
    ];
}

function get_assigned_lead_count($conn, $user_id, $table) {
    $query = "SELECT COUNT(*) as count FROM `$table` WHERE assigned_to = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "i", $user_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);
    return $row['count'];
}

function assign_leads_to_user($conn, $user_id, $table, $count, $zip_codes) {
    $zip_condition = "";
    $zip_array = [];
    if (!empty($zip_codes)) {
        $zip_array = explode(',', $zip_codes);
        $zip_placeholders = implode(',', array_fill(0, count($zip_array), '?'));
        $zip_condition = "AND zip IN ($zip_placeholders)";
    }

    $query = "UPDATE `$table` SET assigned_to = ? WHERE assigned_to IS NULL $zip_condition ORDER BY RAND() LIMIT ?";
    $stmt = mysqli_prepare($conn, $query);

    $types = "i" . str_repeat('s', count($zip_array)) . "i";
    $params = array_merge([$user_id], $zip_array, [$count]);
    mysqli_stmt_bind_param($stmt, $types, ...$params);

    mysqli_stmt_execute($stmt);
    return mysqli_stmt_affected_rows($stmt);
}
function clear_random_user_leads($conn, $user_id, $table, $count) {
    $query = "UPDATE `$table` SET assigned_to = NULL WHERE assigned_to = ? ORDER BY RAND() LIMIT ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ii", $user_id, $count);
    mysqli_stmt_execute($stmt);
    return mysqli_stmt_affected_rows($stmt);
}
