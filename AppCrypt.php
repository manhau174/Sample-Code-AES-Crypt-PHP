<?php
class AppCrypt {
    // DEFINE our cipher
    const AES_256_CBC = 'aes-256-cbc';
    public $key;

    function __construct($key) {
        $this->key = $key;
    }

    public function encrypt($data) {
        // Generate a 256-bit encryption key $encryption_key
        // This should be stored somewhere instead of recreating it each time
        // $encryption_key = openssl_random_pseudo_bytes(32);

        // Generate an initialization vector
        // This *MUST* be available for decryption as well
        $iv = random_bytes(openssl_cipher_iv_length(self::AES_256_CBC)); //16

        // Encrypt $data using aes-256-cbc cipher with the given encryption key and
        // our initialization vector. The 0 gives us the default options, but can
        // be changed to OPENSSL_RAW_DATA or OPENSSL_ZERO_PADDING
        $encrypted = openssl_encrypt($data, self::AES_256_CBC, $this->key, 0, $iv);

        // If we lose the $iv variable, we can't decrypt this, so:
        // - $encrypted is already base64-encoded from openssl_encrypt
        // - Append a separator that we know won't exist in base64, ":"
        // - And then append a base64-encoded $iv

        $encrypted = $encrypted . ':' . base64_encode($iv);

        return base64_encode($encrypted);
    }

    public function decrypt($dataEncrypted) {
        // To decrypt, separate the encrypted data from the initialization vector ($iv).
        $parts = explode(':', base64_decode($dataEncrypted));
        // $parts[0] = encrypted data
        // $parts[1] = base-64 encoded initialization vector

        // Don't forget to base64-decode the $iv before feeding it back to
        //openssl_decrypt
        $decrypted = openssl_decrypt($parts[0], self::AES_256_CBC, $this->key, 0, base64_decode($parts[1]));

        return $decrypted;

    }
}
