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

function get_lead_assignment_stats($mysqli, $users) {
    $stats = [];
    foreach ($users as $user) {
        // Check connection and reconnect if necessary
        if (!$mysqli->ping()) {
            $mysqli->close();
            $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
            if ($mysqli->connect_error) {
                throw new Exception("Failed to reconnect to database: " . $mysqli->connect_error);
            }
        }
        
        $user_stat = [
            'username' => $user['username'],
            'assignments' => []
        ];
        
        $assignments = $mysqli->query("SELECT * FROM user_table_assignments WHERE user_id = {$user['id']}");
        while ($assignment = $assignments->fetch_assoc()) {
            $table = $assignment['assigned_table'];
            $limit = $assignment['lead_limit'];
            $zip_codes = $assignment['zip_codes'];
            
            $check_column = $mysqli->query("SHOW COLUMNS FROM `$table` LIKE 'assigned_to'");
            if ($check_column->num_rows > 0) {
                $count_query = "SELECT COUNT(*) as count FROM `$table` WHERE assigned_to = {$user['id']} LIMIT 1";
            } else {
                $count_query = "SELECT COUNT(*) as count FROM `$table` LIMIT 1";
            }
            
            $count_result = $mysqli->query($count_query);
            $count = $count_result->fetch_assoc()['count'];
            
            $user_stat['assignments'][] = [
                'table' => $table,
                'limit' => $limit,
                'assigned' => $count,
                'zip_codes' => $zip_codes
            ];
        }
        
        $stats[] = $user_stat;
    }
    
    return $stats;
}

function assign_leads($conn) {
    $users = get_all_users($conn);
    $assigned_count = 0;
    $cleared_count = 0;

    foreach ($users as $user) {
        $assignments = mysqli_query($conn, "SELECT * FROM user_table_assignments WHERE user_id = {$user['id']}");
        while ($assignment = mysqli_fetch_assoc($assignments)) {
            $table = $assignment['assigned_table'];
            $limit = $assignment['lead_limit'];
            $zip_codes = $assignment['zip_codes'];

            // Clear existing leads
            $clear_query = "UPDATE `$table` SET assigned_to = NULL WHERE assigned_to = ?";
            $clear_stmt = mysqli_prepare($conn, $clear_query);
            mysqli_stmt_bind_param($clear_stmt, "i", $user['id']);
            mysqli_stmt_execute($clear_stmt);
            $cleared_count += mysqli_affected_rows($conn);

            // Assign new leads
            $assign_query = "UPDATE `$table` SET assigned_to = ? WHERE assigned_to IS NULL";
            if (!empty($zip_codes)) {
                $zips = explode(',', $zip_codes);
                $zip_placeholders = implode(',', array_fill(0, count($zips), '?'));
                $assign_query .= " AND zip IN ($zip_placeholders)";
            }
            $assign_query .= " ORDER BY RAND() LIMIT ?";
            
            $assign_stmt = mysqli_prepare($conn, $assign_query);
            $types = "i" . (empty($zip_codes) ? "" : str_repeat('s', count($zips))) . "i";
            $params = array($user['id']);
            if (!empty($zip_codes)) {
                $params = array_merge($params, $zips);
            }
            $params[] = $limit;
            mysqli_stmt_bind_param($assign_stmt, $types, ...$params);
            mysqli_stmt_execute($assign_stmt);
            $assigned_count += mysqli_affected_rows($conn);
        }
    }

    return [
        'message' => "Assigned $assigned_count new leads and cleared $cleared_count old leads.",
        'assigned' => $assigned_count,
        'cleared' => $cleared_count
    ];
}
