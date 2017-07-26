PAPER	= whitepaper-20
TARGET	= $(PAPER).ps
PDFFILE	= $(PAPER).pdf
SRC	= $(PAPER).tex
TEX	= latex


.SUFFIXES: 

all		:	${TARGET}

pdf		:	$(PDFFILE)

%.ps		:	%.dvi
			dvips -o $@ $*
			cp $@ ..

%.dvi		:	%.tex %.bbl
			latex $*

%.pdf		:	%.ps
			echo "quit" | gs -sDEVICE=pdfwrite -sOutputFile=$@ $<

%.bbl		:	%.tex %.bib
			latex $*
			bibtex $*
			latex $*
			latex $*
#			touch $*.tex

clean		:
			\rm -f *.dvi *.log *.aux *.log *.bbl *.blg *.lof *.toc *.bak *~

purge		:	clean
			\rm -fr ${TARGET}
			\rm -fr ${PDFFILE}
