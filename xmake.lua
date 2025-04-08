add_rules("mode.debug", "mode.release")

set_languages("c++17")
add_requires("mdns","fmt")

target("mdnspp")
    set_kind("static")
    add_packages("mdns","fmt")
    add_includedirs("include")
    add_files("src/mdnspp/*.cpp")
    if is_plat("windows") then
        add_cxxflags("/Zc:__cplusplus");
    end


for _, file in ipairs(os.files("example/*.cpp")) do
    local target_name = path.basename(file)
    target(target_name)
        add_packages("mdns","fmt")
        add_deps("mdnspp")
        set_kind("binary")
        add_includedirs("include")
        add_files(file)
end