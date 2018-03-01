<?php

namespace core;

class JWT_l {

  private static $algoritms = array(
    'HS256' => 'sha256',
    'HS384' => 'sha384',
    'HS512' => 'sha512'
  );

  /**
   * @param $alg {String} Algoritm [HS256, HS384, HS512, bcrypt]
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
   * @param $alg {String} Algoritm [HS256, HS384, HS512, bcrypt]
   * @param $secret {String} Salt
   *
   * @return string
   * @throws Exception
   */
  private function make_signature($data, $alg, $secret) {
    // TODO more algorim
    switch ($alg) {
      case 'HS256':
      case 'HS384':
      case 'HS512':
        $response = hash_hmac(self::$algoritms[$alg], $data, $secret);
        break;

      case 'bcrypt':
        $response = crypt($data, $secret);
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
   * @param $alg {String} Algoritm [HS256, HS384, HS512(default), bcrypt]
   *
   * @return string
   */
  public static function make_token($payload, $secret, $alg = 'HS512') {
    $response = self::make_header($alg) . '.' . self::make_payload($payload);
    $response .= '.' . self::make_signature($response, $alg, $secret);

    return $response;
  }

  /**
   * @param $token {String} JWT Token
   * @param $secret {String} Salt
   * @param $alg {String} Algoritm [HS256, HS384, HS512(default)]
   *
   * @return bool
   */
  public static function verify_token($token, $secret, $alg = 'HS512') {
    $return  = array('success' => false);
    $periods = explode('.', $token);

    if (count($periods) === 3) {
      $header  = base64_decode($periods[0]);
      $payload = base64_decode($periods[1]);
      $header  = json_decode($header);
      $payload = json_decode($payload);
      if ($alg === 'bcrypt') {
        $authorizate = hash_equals($periods[2], crypt($periods[0] . '.' . $periods[1], $secret));
      } else {
        $authorizate = $periods[2] === self::make_signature($periods[0] . '.' . $periods[1], $alg, $secret);
      }
      if ($authorizate) {
        $return['success'] = true;

        if (isset($payload->exp) && (int)$payload->exp < time()) {
          $return['success'] = false;
          $return['msg']     = 'Expired';
        }

        if (isset($payload->nbf) && (int)$payload->nbf > time()) {
          $return['success'] = false;
          $return['msg']     = 'Not before';
        }
      }
    }

    return $return;
  }
}
