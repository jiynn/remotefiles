<?php

//last before updates

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

function clear_leads($conn, $user_id = 0, $assigned_table = '') {
    try {
        error_log("Starting clear_leads process for user_id: $user_id, table: $assigned_table");
        
        if (empty($assigned_table)) {
            throw new Exception("Table name is required");
        }

        $query = "UPDATE `$assigned_table` SET assigned_to = NULL WHERE 1=1";
        $params = [];
        $types = "";

        if ($user_id > 0) {
            $query .= " AND assigned_to = ?";
            $params[] = $user_id;
            $types .= "i";
        }

        $stmt = mysqli_prepare($conn, $query);
        if (!empty($params)) {
            mysqli_stmt_bind_param($stmt, $types, ...$params);
        }

        $result = mysqli_stmt_execute($stmt);

        if ($result) {
            $affected_rows = mysqli_stmt_affected_rows($stmt);
            $message = "Successfully cleared $affected_rows leads from $assigned_table";
            error_log($message);
            return ['success' => true, 'message' => $message];
        } else {
            throw new Exception("Failed to clear leads: " . mysqli_error($conn));
        }
    } catch (Exception $e) {
        error_log("Error in clear_leads: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
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

function assign_leads($conn, $user_id, $assigned_table) {
    $query = "SELECT lead_limit FROM user_table_assignments 
              WHERE user_id = ? AND assigned_table = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "is", $user_id, $assigned_table);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);
    $lead_limit = $row['lead_limit'];

    $count_query = "SELECT COUNT(*) as count FROM `$assigned_table` 
                    WHERE assigned_to = ?";
    $count_stmt = mysqli_prepare($conn, $count_query);
    mysqli_stmt_bind_param($count_stmt, "i", $user_id);
    mysqli_stmt_execute($count_stmt);
    $count_result = mysqli_stmt_get_result($count_stmt);
    $count_row = mysqli_fetch_assoc($count_result);
    $current_assigned = $count_row['count'];

    if ($current_assigned >= $lead_limit) {
        return ['success' => true, 'message' => "Lead limit already met. No new leads assigned."];
    }

    $leads_to_assign = $lead_limit - $current_assigned;

    $assign_query = "UPDATE `$assigned_table` SET assigned_to = ? 
                     WHERE assigned_to IS NULL 
                     ORDER BY RAND() LIMIT ?";
    $assign_stmt = mysqli_prepare($conn, $assign_query);
    mysqli_stmt_bind_param($assign_stmt, "ii", $user_id, $leads_to_assign);
    $result = mysqli_stmt_execute($assign_stmt);

    if ($result) {
        $assigned_count = mysqli_stmt_affected_rows($assign_stmt);
        return ['success' => true, 'message' => "Assigned $assigned_count new leads to user $user_id in table $assigned_table"];
    } else {
        return ['success' => false, 'message' => "Failed to assign leads: " . mysqli_error($conn)];
    }
}
