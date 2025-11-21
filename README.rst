Pentagrid's ``riskless-pain`` tool helps you to review and diff pain.001 files, especially pain001 files for reoccuring monthly salary payments. Diff-like QT-GUI approach for pain.001.001 files of ISO 20022.

Short introduction
==================

There is a lack of tools for reviewing pain.001 files. You may receive them from a
payroll accounting service and upload them into your e-banking, where most of them do not
support a review of the individual transactions. Pentagrid's ``riskless-pain`` tool helps you
to review pain.001 files and supports you in highlighting differences between payment
files, for example for salary payments for different months.

`Our blog post on the occasion of releasing this tool
<https://www.pentagrid.ch/en/blog/pain001-interfaces-and-payment-of-your-salary/>`_ has
more background information regarding this project.

Installation
=============

For Windows and MacOS there are binaries in the releases: https://github.com/pentagridsec/riskless-pain/releases

For Linux users it is simpler to just run it with your local Python installation (next section).

Running with your local Python
==============================

In order to install the software into a virtual Python environment, just run:

::

  $ virtualenv .venv
  $ source .venv/bin/activate
  $ pip install .
  $ risklesspain
  $ risklesspain --test

Copyright and Licence
=====================

``riskless-pain`` is developed by Tobias Ospelt <tobias@pentagrid.ch> and
published under a BSD licence. Please read ``LICENSE.txt`` for further details.
