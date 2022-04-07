cmake_minimum_required(VERSION 3.5)
project(mysniffer-doc VERSION 0.1 LANGUAGES CXX)
find_program(PANDOC NAMES pandoc)
if(PANDOC)
	cmake_path(CONVERT "${CMAKE_CURRENT_SOURCE_DIR}/report.md" TO_NATIVE_PATH_LIST REPORT_MD NORMALIZE)
	cmake_path(CONVERT "${CMAKE_CURRENT_BINARY_DIR}/report.pdf" TO_NATIVE_PATH_LIST REPORT_PDF NORMALIZE)
	add_custom_command(
		OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/report.pdf"
		COMMAND "${PANDOC}" --pdf-engine=xelatex -V mainfont="SimSun" -f markdown "${REPORT_MD}" -o "${REPORT_PDF}"
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} 
		USES_TERMINAL
	)
	add_custom_target(doc ALL DEPENDS "${REPORT_PDF}")
	install(CODE "execute_process(COMMAND \"${CMAKE_COMMAND}\" -E make_directory \"${CMAKE_INSTALL_PREFIX}/doc\")")
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/report.pdf" DESTINATION "${CMAKE_INSTALL_PREFIX}/doc")
else()
	message(WARNING "pandoc not found. Cannot generate report.")
endif()
