# OptimusPrime
UDP stream tsanalyzer
1. A basic implementation.
2. Requires prior knowledge of incoming streams (for better analysis)
3. Generates analysis logs in a file


*BUILD INSTRUCTIONS:*
#FOR UDP STREAM ANALYSIS
@# $(CC) op_tsanalyzer.c -o opts_streamlyzer

#FOR FILE ANALYSIS
@# $(CC) -DFILE_BASED op_tsanalyzer.c -o opts_filelyzer


*EXEC INSTRUCTIONS:*
#FOR UDP STREAM ANALYSIS
@# ./opts_streamlyzer <UDP_PORT> <TSPID_TO_ANALYZE>

#FOR FILE ANALYSIS
@# ./opts_filelyzer <FILE_NAME> <TSPID_TO_ANALYZE>
