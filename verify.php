<?php
header('Content-Type: application/json');

// Definir la clave/contraseña autorizada requerida
define('VALID_KEY', '@VEXTUCRACKED');

// 1. Conexión SQLite local automática (crea un archivo database.sqlite si no existe)
try {
    $pdo = new PDO('sqlite:' . __DIR__ . '/database.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Crear la tabla si no existe
    $pdo->exec("CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE,
        ip_address TEXT,
        expires_at TEXT
    )");
} catch (Exception $e) {
    echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
    exit;
}

// 2. Obtener la IP del cliente (o la de prueba)
$client_ip = $_SERVER['HTTP_X_TEST_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

// 3. Obtener el JSON enviado
$input = json_decode(file_get_contents('php://input'), true);
$key = $input['key'] ?? '';

// 4. Validar que la key sea la correcta (actúa como key y contraseña a la vez)
if (empty($key)) {
    echo json_encode(["success" => false, "message" => "❌ Key is missing."]);
    exit;
}

if ($key !== VALID_KEY) {
    echo json_encode(["success" => false, "message" => "❌ Invalid key."]);
    exit;
}

// 5. Buscar la clave en la base de datos local
$stmt = $pdo->prepare("SELECT * FROM licenses WHERE license_key = ?");
$stmt->execute([$key]);
$license = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$license) {
    // Si la clave válida no está registrada aún, la creamos automáticamente
    $expires_at = date('Y-m-d H:i:s', strtotime('+24 hours'));
    $insert = $pdo->prepare("INSERT INTO licenses (license_key, ip_address, expires_at) VALUES (?, ?, ?)");
    $insert->execute([$key, $client_ip, $expires_at]);

    echo json_encode([
        "success" => true,
        "message" => "✅ Key activated! Your IP is now active for 24 hours.",
        "data" => ["expires_at" => $expires_at]
    ]);
    exit;
}

$registered_ip = $license['ip_address'];
$expires_at = $license['expires_at'];

// 6. Validar o actualizar la IP
if (empty($registered_ip) || $registered_ip === $client_ip) {
    if (empty($registered_ip)) {
        $expires_at = date('Y-m-d H:i:s', strtotime('+24 hours'));
        $update = $pdo->prepare("UPDATE licenses SET ip_address = ?, expires_at = ? WHERE license_key = ?");
        $update->execute([$client_ip, $expires_at, $key]);
    }

    echo json_encode([
        "success" => true,
        "message" => "✅ Key verified successfully.",
        "data" => ["expires_at" => $expires_at]
    ]);
} else {
    echo json_encode([
        "success" => false,
        "message" => "❌ This key is locked to another IP.",
        "data" => null
    ]);
}
?>

