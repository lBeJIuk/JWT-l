<?php


class JWT {

  /**
   * @param $alg {String} Algoritm [HS256, HS384, HS512]
   *
   * @return {String}
   */
  private function make_header($alg) {
    $header = array(
      'alg' => $alg,
      'typ' => 'JWT'
    );
    $header = base64_encode(json_encode($header));

    return $header;
  }

  /**
   * @param $payload {String}
   *
   * @return string
   * @throws Exception
   */
  private function make_payload($payload) {
    if (is_array($payload)) {
      $payload = base64_encode(json_encode($payload));
    } else {
      throw new Exception('Payload must be assotiatives masiv');
    }

    return $payload;
  }

  /**
   * @param $data {String} base64($header).base64($payload)
   * @param $alg {String} Algoritm [HS256, HS384, HS512]
   * @param $secret {String} Salt
   *
   * @return string
   * @throws Exception
   */
  private function make_signature($data, $alg, $secret) {
    // TODO more algorim
    switch ($alg) {
      case 'HS256':
        $response = hash_hmac('sha256', $data, $secret);
        break;

      case 'HS384':
        $response = hash_hmac('sha384', $data, $secret);
        break;

      case 'HS512':
        $response = hash_hmac('sha512', $data, $secret);
        break;

      default:
        throw new Exception('Unsupported encoding');
        break;
    }

    return $response;
  }

  /**
   * @param $payload {Array}
   * @param $secret {String} Salt
   * @param $alg {String} Algoritm [HS256, HS384, HS512(default)]
   *
   * @return string
   */
  public static function make_token($payload, $secret, $alg = 'HS512') {
    try {
      $response = self::make_header($alg) . '.' . self::make_payload($payload);
      $response .= '.' . self::make_signature($response, $alg, $secret);

      return $response;
    } catch (Exception $e) {
      echo $e->getMessage();
    }
  }

  /**
   * @param $token {String} JWT Token
   * @param $secret {String} Salt
   *
   * @return bool
   */
  public static function verify_token($token, $secret) {
    $periods = explode('.', $token);

    if (count($periods) === 3) {
      $header  = base64_decode($periods[0]);
      $payload = base64_decode($periods[1]);

      if(is_object($header) && is_object($header)){
        try {
          $header  = json_decode($header);
          $payload = json_decode($payload);
          $signature = self::make_signature($periods[0] . '.' . $periods[1], $header->alg, $secret);
          if ($signature === $periods[2]) {
            return true;
          }
        } catch (Exception $e){
          echo $e->getMessage();
        }
      }
    }
    return false;
  }
}

?>