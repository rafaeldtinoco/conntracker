
INCL += `pkg-config --cflags glib-2.0`
LIBS += `pkg-config --libs glib-2.0`
LIBS += `pkg-config --libs libmnl`
LIBS += `pkg-config --libs libnetfilter_conntrack`
LIBS += `pkg-config --libs libnetfilter_log`

PROGRAM += conntracker
SOURCES += conntracker.c general.c flows.c nlmsg.c footprint.c

#FLAGS=-Wall -O2
FLAGS=-O2
DEBUG=$(FLAGS) -g -ggdb -DDEBUG

all:
	gcc -I. $(INCL) $(FLAGS) -o $(PROGRAM) $(SOURCES) $(LIBS)

debug:
	gcc -I. $(INCL) $(DEBUG) -o $(PROGRAM) $(SOURCES) $(LIBS)

clean:
	rm -f $(PROGRAM)
	rm -f $(TEST)
