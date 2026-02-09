Basically...
update submodules to oasis origin latest branch (per one of the extensive answers here):
https://stackoverflow.com/questions/5828324/update-git-submodule-to-latest-commit-on-origin
git submodule update --init --recursive --remote


do a check to confirm correct submodule commits (per git doc here):
https://git-scm.com/docs/git-submodule
git submodule foreach 'echo $sm_path `git rev-parse HEAD`'

Output confirms the schema 2.1 correct commit is pinned:
Entering 'stix2validator/schemas-2.0'
stix2validator/schemas-2.0 b155093705ab4934ee29e7ba4dc99ed053cd4e7f
Entering 'stix2validator/schemas-2.1'
stix2validator/schemas-2.1 c4f8d589acf2bdb3783655c89e0ffb6e150006ae

Push from local to my repo (fork of Oasis) which then feeds the change to the PR on Oasis.  I've updated the comments in the PR to confirm.
