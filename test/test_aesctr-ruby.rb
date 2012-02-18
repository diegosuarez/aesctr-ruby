require 'helper'

class TestAesctrRuby < Test::Unit::TestCase
  should "be equal before and after crypt" do
	plain= "Hola mundo del cifrado!"
	pass = "contrasena"
	puts "Cadena original:"+plain
	puts "Contrasena:"+pass
	assert_equal plain, AesCtr.decrypt(AesCtr.encrypt(plain, pass, 192), pass, 192)
  end
end
