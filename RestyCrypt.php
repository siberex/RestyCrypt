<?php
/**
 * Nginx Encrypted Session module
 * Encryption and decryption with PHP
 *
 * https://github.com/openresty/encrypted-session-nginx-module
 *
 *
 * User: www.sib.li
 * Date: 19.03.15
 * Time: 7:11
 */

date_default_timezone_set('Europe/London');


// Use the same values in your nginx config, e.g.:
// encrypted_session_key "SomeSecret, MustBe 32 bytes long";
// encrypted_session_iv "someIV,eq16bytes";

// Key must be 32 bytes long (256 bits)
$key        = 'SomeSecret, MustBe 32 bytes long';
// IV must be exactly 16 bytes long (AES-256 blocksize = 128 bits)
$iv         = 'someIV,eq16bytes';



// Fixed init vector is evil in most cases, but good in case of multi-server nginx cluster
// See also:
// https://github.com/openresty/encrypted-session-nginx-module/issues/2

// Nginx Encrypted Session module uses AES-256 with simple MAC (MD5 of message, not HMAC):
// https://github.com/openresty/encrypted-session-nginx-module/blob/master/src/ngx_http_encrypted_session_cipher.c
// See also:
// https://github.com/openresty/encrypted-session-nginx-module/issues/3
//
// Note: AES-256 is RIJNDAEL-128 (when used with a 256 bit key).

$blockSize  = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$ivSize     = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$macSize    = 16;   // MD5 length in bytes
$timingSize = 8;    // 64-bit long


class RestyCrypt
{

    public function decrypt($text = '')
    {

        // Cipher text (binary), base64-encoded

        // Expires was set to 0 (encrypted_session_expires 0;)
        // $encrypted          = 'lINbAuh1GsUUhV+60Pi+fTeJYUbajr6b51BnJ2dbkreLK7jKv/TkaAYbLot8HRpfPUuUfV8jmjyBHNOCeTNDkg==';

        // Expires was set to default (encrypted_session_expires 1d;)
        $encrypted          = 'eX0isqKuTth9EHvik7Wb+zeJYUbajr6b51BnJ2dbkreLK7jKv/TkaAYbLot8HRpfQW/MAkd3d5sY44bjJ5yo2w==';


        // Binary representation
        $secretMessage      = base64_decode($encrypted);

        // Extract MAC from cipher text
        $macDec             = substr($secretMessage, 0, $macSize);

        // Cipher without MAC
        $secretMessageNoMac = substr($secretMessage, $macSize);

        // Decipher
        $decrypted          = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $secretMessageNoMac, MCRYPT_MODE_CBC, $iv);

        // Remove PKCS#7 padding
        $decryptedUnpadded  = pkcs7unpad($decrypted, $blockSize);

        // Calculate MAC for the message
        $macDecCheck        = hash('md5', $decryptedUnpadded, true);

        // Strip-out expiration time
        $timing             = substr($decryptedUnpadded, -$timingSize);

        // Decrypted text without expiration time
        $plainTextDec       = substr($decryptedUnpadded, 0, -$timingSize);

        // Silly conversion int64 → int32
        $timingInt32Bin     = substr($timing, 4);
        // Unpack from binary big endian byte order
        $timingUnpacked     = unpack('N', $timingInt32Bin);

        // Get DateTime representation
        $dt                 = \DateTime::createFromFormat( 'U', $timingUnpacked[1] );


        echo sprintf( "Encrypted b64:\t%s\n",   $encrypted );
        echo sprintf( "Encrypted hex:\t%s\n",   bin2hex($secretMessage) );
        echo sprintf( "Mac (decrypt):\t%s\n",   bin2hex($macDec) );
        echo sprintf( "Decrypted hex:\t%s\n",   bin2hex($decrypted) );
        echo sprintf( "Unpadded (dec):\t%s\n",  bin2hex($decryptedUnpadded) );
        echo sprintf( "MAC is OK:\t%s\n",       ($macDecCheck === $macDec ? 'YES' : 'NO')  );
        echo sprintf( "Plain hex:\t%s\n",       bin2hex($plainTextDec) );
        echo sprintf( "Timing hex:\t%s\n",      bin2hex($timing) );
        echo sprintf( "Timing int:\t%s\n",      $timingUnpacked[1] );
        echo sprintf( "Timing (dec):\t%s\n",    $dt->format('r') );
        echo sprintf( "Plain text:\t%s\n",      $plainTextDec );

    } // decrypt

    public function encrypt($text = '')
    {
        $plaintextPlain     = 'This is THE TEXT to be Encrypted!';

        // Emulate encrypted_session_expires 1d;
        //$timing             = time() + 86400;

        // Also you can set it to 0:
        //$timing             = 0;

        // Here is exact value from decryption example (above):
        $timing             = 1426974492;


        // Convert 32-bit int to network byte order with 64-bit padding ( analogue in C: htonll() )
        $timingBE           = htonl(0) . htonl($timing);

        // Add expiration time to the text
        $plaintextTimed     = $plaintextPlain . $timingBE;

        // Add PKCS#7 padding to the text
        $plaintextPadded    = pkcs7pad($plaintextTimed, $blockSize);

        // Get DateTime representation
        $dt                 = \DateTime::createFromFormat( 'U', $timing );

        // Correct way to do HMAC is this:
        // $mac = hash_hmac('md5', $cipherText, $anotherKey, true);

        // But Encrypted Session module uses simple MD5 of text:
        $macEnc             = hash('md5', $plaintextTimed, true);

        // Encrypt message
        $ciphertext         = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $plaintextPadded, MCRYPT_MODE_CBC, $iv);

        // Add MAC
        $ciphertextMac      = $macEnc . $ciphertext;


        echo sprintf( "Plain text:\t%s\n",      $plaintextPlain );
        echo sprintf( "Timing (enc):\t%s\n",    $dt->format('r') );
        echo sprintf( "Timing int:\t%s\n",      $timing );
        echo sprintf( "Timing hex:\t%s\n",      bin2hex($timingBE) );
        echo sprintf( "Plain hex:\t%s\n",       bin2hex($plaintextPlain) );
        echo sprintf( "Unpadded (enc):\t%s\n",  bin2hex($plaintextTimed) );
        echo sprintf( "Padded (enc):\t%s\n",    bin2hex($plaintextPadded) );
        echo sprintf( "Mac (encrypt):\t%s\n",   bin2hex($macEnc) );
        echo sprintf( "Encrypted hex:\t%s\n",   bin2hex($ciphertextMac) );
        echo sprintf( "Encrypted b64:\t%s\n",   base64_encode($ciphertextMac) );
    } // encrypt

    /**
     * Right-pads the data string with 1 to n bytes according to PKCS#7,
     * where n is the block size.
     * The size of the result is x times n, where x is at least 1.
     *
     * The version of PKCS#7 padding used is the one defined in RFC 5652 chapter 6.3.
     * This padding is identical to PKCS#5 padding for 8 byte block ciphers such as DES.
     *
     * @param string $plaintext the plaintext encoded as a string containing bytes
     * @param integer $blocksize the block size of the cipher in bytes
     * @return string the padded plaintext
     */
    protected static function pkcs7pad($plaintext, $blocksize)
    {
        $padsize = $blocksize - (strlen($plaintext) % $blocksize);
        return $plaintext . str_repeat(chr($padsize), $padsize);
    } // pkcs7pad

    /**
     * Validates and unpads the padded plaintext according to PKCS#7.
     * The resulting plaintext will be 1 to n bytes smaller depending on the amount of padding,
     * where n is the block size.
     *
     * The user is required to make sure that plaintext and padding oracles do not apply,
     * for instance by providing integrity and authenticity to the IV and ciphertext using a HMAC.
     *
     * Note that errors during uppadding may occur if the integrity of the ciphertext
     * is not validated or if the key is incorrect. A wrong key, IV or ciphertext may all
     * lead to errors within this method.
     *
     * The version of PKCS#7 padding used is the one defined in RFC 5652 chapter 6.3.
     * This padding is identical to PKCS#5 padding for 8 byte block ciphers such as DES.
     *
     * @param string $padded the padded plaintext encoded as a string containing bytes
     * @param integer $blocksize the block size of the cipher in bytes
     * @return string the unpadded plaintext
     * @throws Exception if the unpadding failed
     */
    protected static function pkcs7unpad($padded, $blocksize)
    {
        $l = strlen($padded);

        if ($l % $blocksize != 0) {
            //throw new \Exception("Padded plaintext cannot be divided by the block size");
            return $padded;
        }

        $padsize = ord($padded[$l - 1]);

        if ($padsize === 0) {
            //throw new \Exception("Zero padding found instead of PKCS#7 padding");
            return $padded;
        }

        if ($padsize > $blocksize) {
            //throw new \Exception("Incorrect amount of PKCS#7 padding for blocksize");
            return $padded;
        }

        // check the correctness of the padding bytes by counting the occurance
        $padding = substr($padded, -1 * $padsize);
        if (substr_count($padding, chr($padsize)) != $padsize) {
            //throw new \Exception("Invalid PKCS#7 padding encountered");
            return $padded;
        }

        return substr($padded, 0, $l - $padsize);
    } // pkcs7unpad

    /**
     * Convert 32-bit unsigned integer to a binary string in big endian (network) byte order.
     *
     * @param $n
     * @return string
     */
    protected static function htonl($n)
    {
        $n = (int)$n;
        return (binary)pack('N', $n);
    } // htonl

}
