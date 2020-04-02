MAVEN = mvn

all: capmap rommask

capmap:
	cd capmap-free; ${MAVEN} install -DskipTests; cd ..

rommask:
	${MAVEN} assembly:assembly

clean:
	cd capmap-free; ${MAVEN} clean; cd ..
	${MAVEN} clean
