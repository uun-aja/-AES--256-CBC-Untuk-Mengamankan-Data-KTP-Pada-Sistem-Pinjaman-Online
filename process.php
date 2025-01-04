<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $targetDir = "uploads/";

    if (!file_exists($targetDir)) {
        mkdir($targetDir, 0777, true);
    }

    $fullname = $_POST['fullname'];
    $email = $_POST['email'];
    $phone = $_POST['phone'];
    $custom_key = $_POST['custom_key']; // Ambil kunci dari pengguna

    // Validasi panjang kunci minimal 8 karakter
    if (strlen($custom_key) < 8) {
        die("Kunci harus memiliki panjang minimal 8 karakter.");
    }

    // Padding kunci untuk memenuhi 32 karakter
    $encryption_key = str_pad($custom_key, 32, '0'); // Tambahkan '0' hingga panjangnya 32 karakter

    $iv = openssl_random_pseudo_bytes(16);

    $targetFile = $targetDir . basename($_FILES["ktp"]["name"]);
    if (move_uploaded_file($_FILES["ktp"]["tmp_name"], $targetFile)) {
        $data = file_get_contents($targetFile);

        // Enkripsi data dengan AES-256-CBC menggunakan kunci yang diproses
        $ciphertext = openssl_encrypt($data, 'AES-256-CBC', $encryption_key, OPENSSL_RAW_DATA, $iv);
        $encrypted_file = $targetFile . ".enc";
        file_put_contents($encrypted_file, $iv . $ciphertext);
        unlink($targetFile);

        $userData = [
            'fullname' => $fullname,
            'email' => $email,
            'phone' => $phone,
            'file' => basename($encrypted_file),
        ];

        $jsonData = json_encode($userData) . PHP_EOL;
        file_put_contents("uploads/data.json", $jsonData, FILE_APPEND);

        echo "File KTP berhasil dienkripsi dan disimpan sebagai " . basename($encrypted_file);
    } else {
        echo "Gagal mengunggah file.";
    }
} else {
    http_response_code(405);
    die('Hanya metode POST yang diizinkan.');
}
?>
