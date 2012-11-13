<?php

// Set these values to your Redis database
define("REDIS_HOST", "127.0.0.1");
define("REDIS_PORT", 6379);

define("CLIENT_ID_PREFIX","cip_");
define("AUTH_CODE_PREFIX","acp_");
define("ACCESS_TOKEN_PREFIX","atp_");
define("REFRESH_TOKEN_PREFIX","rtp_");

include "../../../lib/OAuth2.inc";

require_once("lib/Predis/Autoloader.php");

/**
 * Sample OAuth2 Library Redis DB Implementation.
 */
class RedisOAuth2 extends OAuth2 {

  private $db;

  /**
   * Overrides OAuth2::__construct().
   */
  public function __construct() {
    parent::__construct();

    Predis\Autoloader::register();
    $this->db = new Predis\Client(
        array(
            array('host'=>REDIS_HOST, 'port'=>REDIS_PORT)
        )
    );
  }

  /**
   * Little helper function to add a new client to the database.
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   *
   * @param $client_id
   *   Client identifier to be stored.
   * @param $client_secret
   *   Client secret to be stored.
   * @param $redirect_uri
   *   Redirect URI to be stored.
   */
  public function addClient($client_id, $client_secret, $redirect_uri) {
    
    $key = CLIENT_ID_PREFIX . $client_id;
    $val = array(
        "_id" => $client_id,
        "pwd" => $client_secret,
        "redirect_uri" => $redirect_uri
    );
    $this->db->setnx($key,json_encode($val));
  }

  /**
   * Implements OAuth2::checkClientCredentials().
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   */
  protected function checkClientCredentials($client_id, $client_secret = NULL) {
    $val = $this->db->get(CLIENT_ID_PREFIX . $client_id);
    if($val != false){
        
        $val = json_decode($val,true);
        if($val["_id"] == $client_id && $val["pwd"] == $client_secret){return true;}
    }
    return $val;
  }


  /**
   * Implements OAuth2::checkClientCredentials().
   *
   */
  protected function checkUserCredentials($client_id, $username, $password) {
    //check whether account information is correct
    if(!($username == "ciaos" && $password == "ciaospwd")){
        return false;
    }
    //check whether it's a valid client
    $val = $this->db->get(CLIENT_ID_PREFIX . $client_id);
    return $val;
  }

  /**
   * Implements OAuth2::getRedirectUri().
   */
  protected function getRedirectUri($client_id) {
    $val = $this->db->get(CLIENT_ID_PREFIX . $client_id);
    if($val != false){
        $val = json_decode($val,true);
    }
    else{
        return false;
    }
    return $val["redirect_uri"];
  }

  /**
   * Implements OAuth2::getAccessToken().
   */
  protected function getAccessToken($oauth_token) {
    $val = $this->db->get(ACCESS_TOKEN_PREFIX . $oauth_token);
    if($val != false){
        return json_decode($val,true);
    }
    else{
        return false;
    }
  }
  
  /**
   * Implements OAuth2::setAccessToken().
   */
  protected function setAccessToken($oauth_token, $client_id, $expires, $scope = NULL) {
    $key = ACCESS_TOKEN_PREFIX . $oauth_token;
    $val = array(
      "_id" => $oauth_token,
      "client_id" => $client_id,
      "expires" => $expires,
      "scope" => $scope
    );
    $this->db->set($key, json_encode($val));
  }
  
  /**
   * Implements OAuth2::setRefreshToken().
   */
  protected function setRefreshToken($refresh_token, $client_id, $expires, $scope = NULL) {
    $key = REFRESH_TOKEN_PREFIX . $refresh_token;
    $val = array(
      "_id" => $refresh_token,
      "client_id" => $client_id,
      "expires" => $expires,
      "scope" => $scope
    );
    
    $this->db->set($key, json_encode($val));
  }
  
  /**
   * Implements OAuth2::getRefreshToken().
   */
  protected function getRefreshToken($refresh_token) {
    $val = $this->db->get(REFRESH_TOKEN_PREFIX . $refresh_token);
    if($val != false){
        return json_decode($val,true);
    }
    else{
        return false;
    }
  }

  /**
   * Overrides OAuth2::getAuthCode().
   */
  protected function getAuthCode($code) {
    
    $val = $this->db->get(AUTH_CODE_PREFIX . $code);
    if($val != false){
        return json_decode($val,true);
    }
    else{
        return false;
    }
  }

  /**
   * Overrides OAuth2::setAuthCode().
   */
  protected function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = NULL) {
    
    $key = AUTH_CODE_PREFIX . $code;
    $val = array(
      "_id" => $code,
      "client_id" => $client_id,
      "redirect_uri" => $redirect_uri,
      "expires" => $expires,
      "scope" => $scope
    );
    
    $this->db->set($key, json_encode($val));
  }
  
  /**
   * Overrides OAuth2::getSupportedGrantTypes().
   */
  protected function getSupportedGrantTypes() {
    return array(
      OAUTH2_GRANT_TYPE_AUTH_CODE,
      OAUTH2_GRANT_TYPE_USER_CREDENTIALS,
      OAUTH2_GRANT_TYPE_REFRESH_TOKEN
    );
  }
}
