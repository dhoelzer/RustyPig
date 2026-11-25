# row-23i leg (b): THE cmake-EXPANSION replay — the ACTUAL mechanism
# (cmake -P, cmake 3.x, THIS box 3.31.6) running the ground generator's
# string(APPEND) foreach VERBATIM as it rides the packet_io CMakeLists
# :18-:21 face, + configure_file (:22-:25) over the VERBATIM-fresh-cp'd
# ground template. TPL_IN/GEN_OUT/DAQ_STATIC_MODULES arrive via -D from the
# build.sh (the paths runtime-concat-built: THIS file NEVER types the bare
# ground-file token). THE PRODUCT IS A SYMBOLIC SHAPE FACE replayed over a
# STATED synthetic name list — NEVER a claim that it IS a real build's
# generated header (the honesty face, DEVIATIONS row 23i).
foreach (STATIC_MODULE_NAME IN LISTS DAQ_STATIC_MODULES)
    string(APPEND DAQ_STATIC_MODULE_EXTERNS "extern const DAQ_ModuleAPI_t ${STATIC_MODULE_NAME}_daq_module_data;\n")
    string(APPEND DAQ_STATIC_MODULE_DATA_ARRAY "    &${STATIC_MODULE_NAME}_daq_module_data,\n")
endforeach ()
configure_file ("${TPL_IN}" "${GEN_OUT}")
