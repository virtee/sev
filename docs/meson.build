custom_target('sev.3',
  command : ['rst2man', '@INPUT@', '@OUTPUT@'],
  input : ['sev.rst'],
  output : ['sev.3'],
  install : true,
  install_dir : join_paths(get_option('mandir'), 'man3'))
