all:
	@echo "make install | install_with_break | uninstall | sdist"

.PHONY: all install install_with_break uninstall uninstall_with_break sdist clean

sdist:
	python3 setup.py sdist

install:
	python3 setup.py clean --all
	pip3 install --no-cache-dir --upgrade .
	sudo pigadget-mcp-install-service --enable --start

install_with_break:
	python3 setup.py clean --all
	pip3 install --no-cache-dir --upgrade --break-system-packages .
	sudo pigadget-mcp-install-service --enable --start

uninstall:
	pip3 uninstall --yes pigadget-mcp

uninstall_with_break:
	pip3 uninstall --yes pigadget-mcp --break-system-packages

clean:
	rm -rf build dist *.egg-info pigadget_mcp/__pycache__ __pycache__
