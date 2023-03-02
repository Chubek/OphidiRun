BUILD_DIR := ./build
SRC_DIRS := ./src

SRCS := $(shell find $(SRC_DIRS)/slitherbrain -name '*.cpp')
INC_FLAGS := -I$(SRC_DIRS)/includes

CCX = g++
CCX_FLAGS = $(DEBUG)

LIB = -lseccomp

out_brain := $(BUILD_DIR)/slitherbrain
otu_run := $(BUILD_DIR)/slitherrun


all: clean mk slitherbrain slitherrun

mk:
	mkdir -p $(BUILD_DIR)

slitherbrain:
	$(CCX) $(CCX_FLAGS) $(INC_FLAGS) $(SRC_DIRS)/slitherbrain.cpp $(SRCS) $(LIB) -o $(out_brain)

slitherrun:
	$(CCX) $(CCX_FLAGS) $(INC_FLAGS) $(SRC_DIRS)/slitherrun.cpp $(SRCS)  $(LIB) -o $(otu_run)

clean:
	bash -c "if [ -d ${BUILD_DIR} ]; then rm -f ${out_brain} ${out_run}; fi"
