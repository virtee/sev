project('sev', ['c', 'rust'],
  meson_version: '>=0.61.0',
  license : 'Apache-2.0',
  version : run_command(['python', './package-version.py'], check : true).stdout().strip(),
  default_options : ['buildtype=release'],
)

find_program('cargo', required: true)

add_project_arguments(
  '-D_GNU_SOURCE',
  language : 'c',
)

subdir('docs')
subdir('include')
subdir('src') # requires: include

sev_dep = declare_dependency(include_directories: inc,
                             link_with: lib)
