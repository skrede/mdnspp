if (TARGET mdnspp::encrypt)
    add_executable(mdnspp_encrypt_01_basic_observer 01_basic_observer.cpp)
    target_link_libraries(mdnspp_encrypt_01_basic_observer PRIVATE mdnspp::mdnspp mdnspp::encrypt)

    add_executable(mdnspp_encrypt_02_key_rotation 02_key_rotation.cpp)
    target_link_libraries(mdnspp_encrypt_02_key_rotation PRIVATE mdnspp::mdnspp mdnspp::encrypt)

    add_executable(mdnspp_encrypt_03_auth_only 03_auth_only.cpp)
    target_link_libraries(mdnspp_encrypt_03_auth_only PRIVATE mdnspp::mdnspp mdnspp::encrypt)
endif ()
