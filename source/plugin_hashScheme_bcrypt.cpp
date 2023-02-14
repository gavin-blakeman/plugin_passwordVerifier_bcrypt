#include "include/pluginInterface/interfaceHashScheme.h"

  // C++ library

#include <memory>
#include <random>

  // Miscellaneous libraries

#include <crypt.h>
#include <GCL>

  // engineeringShop header files

#include "include/pluginInterface/interfaceHashScheme.h"

namespace pluginHashScheme
{
  std::string const AUTH_BCRYPT_ROUNDS        ("bcrypt/rounds");

  static GCL::CReaderSections const *configurationReader = nullptr;

  /// @brief Initialise the plugin. Must be called before any password functions are called.
  /// @param[in] cr: Pointer to the configuration file reader.
  /// @throws None
  /// /// @note If this is not called, then defaults will be used.
  /// @version 2022-11-10/GGB - Function created.

  void initialisePlugin(GCL::CReaderSections const *cr)
  {
    configurationReader = cr;
  }

  void __attribute__ ((destructor)) destroyPlugin()
  {
  }


  /// @brief Returns a string containing the hashing method.
  /// @returns Reference to the hashing method
  /// @throws
  /// @version 2022-11-10/GGB - Function created.

  std::string const &hashMethod()
  {
    static std::string const method = "bcrypt";

    return method;
  }

  /// @brief Creates a salt and hash for a new password.
  /// @param[in] salt: The salt created.
  /// @param[in] hash: The hashed password.
  /// @param[in] password: The new password to hash.
  /// @version 2022-07-16/GGB - Function created.

  void createHash(std::string &salt, std::string &hash, std::string const &password)
  {
    std::string chrs = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    constexpr std::uint16_t saltLength = 16;

    salt.clear();
    hash.clear();

    std::optional<std::uint16_t> rounds = configurationReader->tagValueUInt16(AUTH_BCRYPT_ROUNDS);

    if (!rounds)
    {
      rounds = 9;
    }

    std::random_device rd;
    std::default_random_engine e1(rd());
    std::uniform_int_distribution<int> uniform_dist(0, chrs.length()-1);

      // Generate the salt.

    for (auto i = 0; i < saltLength; i++)
    {
      salt.push_back(chrs[uniform_dist(e1)]);
    }
    salt.push_back(0);

      // Generate the hash

    crypt_data data;
    std::string prefix = "$2b$";
    char setting[CRYPT_GENSALT_OUTPUT_SIZE];
    std::string_view svs(setting);

    std::fill(reinterpret_cast<volatile char *>(&data), reinterpret_cast<volatile char *>(&data) + sizeof(data), 0);

    crypt_gensalt_rn(prefix.c_str(), *rounds, salt.c_str(), saltLength, setting, CRYPT_GENSALT_OUTPUT_SIZE);
    crypt_r(password.c_str(), setting, &data);

    std::string_view sv(data.output);

    hash = sv;

      // Zero out the memory. It is on the stack so should get reused fairly quickly.

    std::fill(reinterpret_cast<volatile char *>(&data), reinterpret_cast<volatile char *>(&data) + sizeof(data), 0);
  }

  /// @brief Verifies the passed password.
  /// @param[in] salt: The salt Value. Should not include any of the MCF characters.
  /// @param[in] hash: The hashed value. Must include he MCF characters.
  /// @param[in] passwordL The password to verify.
  /// @version 2022-07-14/GGB - Function created.

  bool authenticate(std::string const &salt, std::string const &hash, std::string const &password)
  {
    bool returnValue = false;
    crypt_data data;
    char setting[CRYPT_GENSALT_OUTPUT_SIZE];

    std::fill(reinterpret_cast<volatile char *>(&data), reinterpret_cast<volatile char *>(&data) + sizeof(data), 0);

    std::cout << "Salt: " << salt << std::endl;
    std::cout << "Hash: " << hash << std::endl;
    std::cout << "Setting: " << setting << std::endl;

    crypt_r(password.c_str(), hash.c_str(), &data);

    std::string_view sv(data.output);

    returnValue = (sv == hash);

      // Zero out the memory. It is on the stack so should get reused fairly quickly.

    std::fill(reinterpret_cast<volatile char *>(&data), reinterpret_cast<volatile char *>(&data) + sizeof(data), 0);

    return returnValue;
  }

} // namespace
