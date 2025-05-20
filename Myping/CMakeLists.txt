cmake_minimum_required(VERSION 3.10)
project(MyPing)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加编译选项
add_compile_options(-Wall)

# 源文件
set(SOURCE_FILES 
    main.cpp
    Myping.cpp
    Myping.h
)

# 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

# 添加链接选项
if(WIN32)
    target_link_libraries(${PROJECT_NAME} ws2_32)
endif()

# Debug 和 Release 配置
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -s")