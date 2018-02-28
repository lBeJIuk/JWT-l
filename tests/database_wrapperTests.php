<?php

use core\DB_WRAPPER;
use PHPUnit\Framework\TestCase;

spl_autoload_register(function($class_name) {
  $file_path = '../api/' . str_replace('\\', '/', $class_name . '.php');
  if (file_exists($file_path)) {
    require $file_path;
  }
});

final class database_wrapperTests extends TestCase {

  public function prepareFieldLisForSelectProvider(){
    return array();
  }
  /**
   * @dataProvider prepareFieldLisForSelectProvider
   */
  public function test_prepareFieldListForSelect($a, $expexted)
  {
    $this->assertEquals(
      $a,
      $expexted
    );
  }
}
