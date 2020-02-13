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

// Side notes...
// Fixed init vector is evil in most cases, but good in case of multi-server nginx cluster
// See also:
// https://github.com/openresty/encrypted-session-nginx-module/issues/2

// Nginx Encrypted Session module uses AES-256 with simple MAC (MD5 of message, not HMAC):
// https://github.com/openresty/encrypted-session-nginx-module/blob/master/src/ngx_http_encrypted_session_cipher.c
// See also:
// https://github.com/openresty/encrypted-session-nginx-module/issues/3


// Note: AES-256 is RIJNDAEL-128 (when used with a 256 bit key).
define('BLOCK_SIZE',
    mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC));

const MAC_SIZE = 16; // MD5 length in bytes
const TIMING_SIZE  = 8; // 64-bit long

/**
 * Class RestyCrypt
 *
 * PHP implementation for OpenResty encrypted-session-nginx-module encryption and decryption methods.
 *
 * @see https://github.com/openresty/encrypted-session-nginx-module/blob/master/src/ngx_http_encrypted_session_cipher.c
 */
class RestyCrypt
{

    /**
     * Key must be 32 bytes long (256 bits)
     * Use the same value for `encrypted_session_key` nginx config variable.
     * For example:
     * ```
     * encrypted_session_key "SomeSecret, MustBe 32 bytes long";
     * ```
     *
     * @var string
     */
    protected $secret = '';
    /**
     * InitVector must be exactly 16 bytes long (AES-256 blocksize = 128 bits).
     * Use the same value for `encrypted_session_iv` nginx config variable.
     * For example:
     * ```
     * encrypted_session_iv "someIV,eq16bytes";
     * ```
     *
     * @var string
     */
    protected $iv = '';

    /**
     * @var int Expiration in seconds from now.
     */
    protected $expiration = 0;


    public function __construct($secret, $iv, $expiration = 0) {
        $this->secret = $secret;
        $this->iv = $iv;
        $this->expiration = $expiration;
    }

    /**
     * Decrypt cipher message.
     *
     * @param string $encrypted Base64-encoded cipher text (binary).
     * @return string? null on decoding error
     */
    public function decrypt($encrypted = '')
    {
        // Binary representation
        $secretMessage      = base64_decode($encrypted);

        // Extract MAC from cipher text
        $macDec             = substr($secretMessage, 0, MAC_SIZE);

        // Cipher without MAC
        $secretMessageNoMac = substr($secretMessage, MAC_SIZE);

        // Decipher
        $decrypted          = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->secret, $secretMessageNoMac, MCRYPT_MODE_CBC, $this->iv);

        // Remove PKCS#7 padding
        $decryptedUnpadded  = self::pkcs7unpad($decrypted, BLOCK_SIZE);

        // Calculate MAC for the message
        $macDecCheck        = hash('md5', $decryptedUnpadded, true);

        // Strip-out expiration time
        $timing             = substr($decryptedUnpadded, -TIMING_SIZE);

        // Decrypted text without expiration time
        $plainTextDec       = substr($decryptedUnpadded, 0, -TIMING_SIZE);

        // Silly conversion int64 → int32
        $timingInt32Bin     = substr($timing, 4);
        // Unpack from binary big endian byte order
        $timingUnpacked     = unpack('N', $timingInt32Bin);

        // Get DateTime representation
        $dt                 = \DateTime::createFromFormat( 'U', $timingUnpacked[1] );

        if ($macDecCheck !== $macDec) {
            return null;
        }

        return $plainTextDec;

        // echo sprintf( "Encrypted b64:\t%s\n",   $encrypted );
        // echo sprintf( "Encrypted hex:\t%s\n",   bin2hex($secretMessage) );
        // echo sprintf( "Mac (decrypt):\t%s\n",   bin2hex($macDec) );
        // echo sprintf( "Decrypted hex:\t%s\n",   bin2hex($decrypted) );
        // echo sprintf( "Unpadded (dec):\t%s\n",  bin2hex($decryptedUnpadded) );
        // echo sprintf( "MAC is OK:\t%s\n",       ($macDecCheck === $macDec ? 'YES' : 'NO')  );
        // echo sprintf( "Plain hex:\t%s\n",       bin2hex($plainTextDec) );
        // echo sprintf( "Timing hex:\t%s\n",      bin2hex($timing) );
        // echo sprintf( "Timing int:\t%s\n",      $timingUnpacked[1] );
        // echo sprintf( "Timing (dec):\t%s\n",    $dt->format('r') );
        // echo sprintf( "Plain text:\t%s\n",      $plainTextDec );
    } // decrypt


    /**
     * Encrypt.
     *
     * @param string $text
     * @return string base64-encoded cipher text (binary)
     */
    public function encrypt($text = '')
    {
        //$plaintextPlain     = 'This is THE TEXT to be Encrypted!';

        $timing = 0;
        if ($this->expiration > 0) {
            $timing = time() + 86400;
        }

        // Convert 32-bit int to network byte order with 64-bit padding ( analogue in C: htonll() )
        $timingBE           = self::htonl(0) . self::htonl($timing);

        // Add expiration time to the text
        $plaintextTimed     = $text . $timingBE;

        // Add PKCS#7 padding to the text
        $plaintextPadded    = self::pkcs7pad($plaintextTimed, BLOCK_SIZE);

        // Get DateTime representation
        $dt                 = \DateTime::createFromFormat( 'U', $timing );

        // Correct way to do HMAC is this:
        // $mac = hash_hmac('md5', $cipherText, $anotherKey, true);

        // But Encrypted Session module uses simple MD5 of text:
        $macEnc             = hash('md5', $plaintextTimed, true);

        // Encrypt message
        $ciphertext         = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->secret, $plaintextPadded, MCRYPT_MODE_CBC, $this->iv);

        // Add MAC
        $ciphertextMac      = $macEnc . $ciphertext;

        return base64_encode($ciphertextMac);

        // echo sprintf( "Plain text:\t%s\n",      $text );
        // echo sprintf( "Timing (enc):\t%s\n",    $dt->format('r') );
        // echo sprintf( "Timing int:\t%s\n",      $timing );
        // echo sprintf( "Timing hex:\t%s\n",      bin2hex($timingBE) );
        // echo sprintf( "Plain hex:\t%s\n",       bin2hex($text) );
        // echo sprintf( "Unpadded (enc):\t%s\n",  bin2hex($plaintextTimed) );
        // echo sprintf( "Padded (enc):\t%s\n",    bin2hex($plaintextPadded) );
        // echo sprintf( "Mac (encrypt):\t%s\n",   bin2hex($macEnc) );
        // echo sprintf( "Encrypted hex:\t%s\n",   bin2hex($ciphertextMac) );
        // echo sprintf( "Encrypted b64:\t%s\n",   base64_encode($ciphertextMac) );
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
    protected static function pkcs7pad($plaintext, $blocksize = BLOCK_SIZE)
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
     */
    protected static function pkcs7unpad($padded, $blocksize = BLOCK_SIZE)
    {
        $l = strlen($padded);

        if ($l % $blocksize !== 0) {
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
        if (substr_count($padding, chr($padsize)) !== $padsize) {
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
