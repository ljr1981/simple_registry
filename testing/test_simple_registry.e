note
	description: "Tests for SIMPLE_REGISTRY library"
	testing: "covers"

class
	TEST_SIMPLE_REGISTRY

inherit
	TEST_SET_BASE
		redefine
			on_prepare,
			on_clean
		end

feature -- Setup

	on_prepare
			-- Set up test fixtures.
		do
			create registry
		end

	on_clean
			-- Clean up after tests.
		do
			-- Clean up any test keys we created
			if registry.key_exists (registry.HKEY_CURRENT_USER, test_subkey) then
				registry.delete_value (registry.HKEY_CURRENT_USER, test_subkey, "TestString")
				registry.delete_value (registry.HKEY_CURRENT_USER, test_subkey, "TestInteger")
				registry.delete_value (registry.HKEY_CURRENT_USER, test_subkey, "ToDelete")
				registry.delete_key (registry.HKEY_CURRENT_USER, test_subkey)
			end
		end

feature -- Access

	registry: SIMPLE_REGISTRY
			-- Registry access object.

	test_subkey: STRING = "Software\SimpleRegistryTest"
			-- Test subkey path (under HKCU).

feature -- Test: Predefined Keys

	test_hkey_constants_not_null
			-- Test that HKEY constants are valid.
		do
			assert ("HKEY_CLASSES_ROOT not null", registry.HKEY_CLASSES_ROOT /= default_pointer)
			assert ("HKEY_CURRENT_USER not null", registry.HKEY_CURRENT_USER /= default_pointer)
			assert ("HKEY_LOCAL_MACHINE not null", registry.HKEY_LOCAL_MACHINE /= default_pointer)
			assert ("HKEY_USERS not null", registry.HKEY_USERS /= default_pointer)
			assert ("HKEY_CURRENT_CONFIG not null", registry.HKEY_CURRENT_CONFIG /= default_pointer)
		end

feature -- Test: Key Exists

	test_known_key_exists
			-- Test that well-known keys exist.
		do
			assert ("SOFTWARE key exists", registry.key_exists (registry.HKEY_LOCAL_MACHINE, "SOFTWARE"))
			assert ("Environment key exists", registry.key_exists (registry.HKEY_CURRENT_USER, "Environment"))
		end

	test_nonexistent_key
			-- Test that nonexistent key returns false.
		do
			assert ("Nonexistent key", not registry.key_exists (registry.HKEY_CURRENT_USER, "ThisKeyDoesNotExist12345"))
		end

feature -- Test: Create/Delete Key

	test_create_and_delete_key
			-- Test creating and deleting a registry key.
		do
			-- Ensure clean state
			if registry.key_exists (registry.HKEY_CURRENT_USER, test_subkey) then
				registry.delete_key (registry.HKEY_CURRENT_USER, test_subkey)
			end

			-- Create key
			registry.create_key (registry.HKEY_CURRENT_USER, test_subkey)
			assert ("Key created", registry.last_operation_succeeded)
			assert ("Key exists after creation", registry.key_exists (registry.HKEY_CURRENT_USER, test_subkey))

			-- Delete key
			registry.delete_key (registry.HKEY_CURRENT_USER, test_subkey)
			assert ("Key deleted", registry.last_operation_succeeded)
			assert ("Key gone after deletion", not registry.key_exists (registry.HKEY_CURRENT_USER, test_subkey))
		end

feature -- Test: Write/Read String

	test_write_and_read_string
			-- Test writing and reading a string value.
		local
			l_value: detachable STRING_32
		do
			-- Create test key
			registry.create_key (registry.HKEY_CURRENT_USER, test_subkey)

			-- Write string
			registry.write_string (registry.HKEY_CURRENT_USER, test_subkey, "TestString", "Hello, Registry!")
			assert ("String write succeeded", registry.last_operation_succeeded)

			-- Verify value exists
			assert ("Value exists", registry.value_exists (registry.HKEY_CURRENT_USER, test_subkey, "TestString"))

			-- Read string back
			l_value := registry.read_string (registry.HKEY_CURRENT_USER, test_subkey, "TestString")
			assert ("String read not void", l_value /= Void)
			if attached l_value as v then
				assert ("String value correct", v.same_string ("Hello, Registry!"))
			end

			-- Clean up
			registry.delete_value (registry.HKEY_CURRENT_USER, test_subkey, "TestString")
			registry.delete_key (registry.HKEY_CURRENT_USER, test_subkey)
		end

feature -- Test: Write/Read Integer

	test_write_and_read_integer
			-- Test writing and reading a DWORD value.
		local
			l_value: INTEGER
		do
			-- Create test key
			registry.create_key (registry.HKEY_CURRENT_USER, test_subkey)

			-- Write integer
			registry.write_integer (registry.HKEY_CURRENT_USER, test_subkey, "TestInteger", 42)
			assert ("Integer write succeeded", registry.last_operation_succeeded)

			-- Read integer back
			l_value := registry.read_integer (registry.HKEY_CURRENT_USER, test_subkey, "TestInteger")
			assert ("Integer read succeeded", registry.last_read_succeeded)
			assert ("Integer value correct", l_value = 42)

			-- Clean up
			registry.delete_value (registry.HKEY_CURRENT_USER, test_subkey, "TestInteger")
			registry.delete_key (registry.HKEY_CURRENT_USER, test_subkey)
		end

feature -- Test: Value Exists

	test_value_exists
			-- Test checking if a value exists.
		do
			-- Create test key and value
			registry.create_key (registry.HKEY_CURRENT_USER, test_subkey)
			registry.write_string (registry.HKEY_CURRENT_USER, test_subkey, "TestString", "test")

			-- Check existence
			assert ("Value exists", registry.value_exists (registry.HKEY_CURRENT_USER, test_subkey, "TestString"))
			assert ("Nonexistent value", not registry.value_exists (registry.HKEY_CURRENT_USER, test_subkey, "NoSuchValue"))

			-- Clean up
			registry.delete_value (registry.HKEY_CURRENT_USER, test_subkey, "TestString")
			registry.delete_key (registry.HKEY_CURRENT_USER, test_subkey)
		end

feature -- Test: Delete Value

	test_delete_value
			-- Test deleting a value.
		do
			-- Create test key and value
			registry.create_key (registry.HKEY_CURRENT_USER, test_subkey)
			registry.write_string (registry.HKEY_CURRENT_USER, test_subkey, "ToDelete", "delete me")
			assert ("Value created", registry.value_exists (registry.HKEY_CURRENT_USER, test_subkey, "ToDelete"))

			-- Delete value
			registry.delete_value (registry.HKEY_CURRENT_USER, test_subkey, "ToDelete")
			assert ("Delete succeeded", registry.last_operation_succeeded)
			assert ("Value gone", not registry.value_exists (registry.HKEY_CURRENT_USER, test_subkey, "ToDelete"))

			-- Clean up
			registry.delete_key (registry.HKEY_CURRENT_USER, test_subkey)
		end

feature -- Test: Read System Values

	test_read_system_string
			-- Test reading a known system string value.
		local
			l_value: detachable STRING_32
		do
			-- Read the ComSpec environment variable from registry
			l_value := registry.read_string (registry.HKEY_LOCAL_MACHINE,
				"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "ComSpec")
			-- This might not exist on all systems, so just check it doesn't crash
			-- If it exists, it should contain cmd.exe
			if attached l_value as v then
				assert ("ComSpec contains cmd", v.as_lower.has_substring ("cmd"))
			end
		end

end
