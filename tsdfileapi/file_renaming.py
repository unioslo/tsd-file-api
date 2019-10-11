
# script to demonstrate the .part filename and data processing logic

import os

path = 'orig.file'
path_part = path + '.part'


def test():

    # if there is a partial file
    # stop the request - this file might
    # be actively written to
    if os.path.lexists(path_part):
        print('%s exists - exiting' % path_part)
        return

    # if the target file exists, rename it to partial
    # so we can safely start writing to the partial one
    if os.path.lexists(path):
        print('%s exits - going to rename it' % path)
        os.rename(path, path_part)
        print('renamed %s to %s' % (path, path_part))
        assert os.path.lexists(path_part)
        assert not os.path.lexists(path)

    print('writing data to %s' % path_part)
    with open(path_part, 'w+') as f:
        f.write('my data')

    # finished writing data
    print('renaming %s to %s' % (path_part, path))
    os.rename(path_part, path)

    # make sure the partial file does not exist anymore
    assert not os.path.lexists(path_part)
    assert os.path.lexists(path)

    # cleanup the test's side-effect
    os.remove(path)

print()
print('test 1: no files exist')
test()

print()
print('test 2: partial file exists')
with open(path_part, 'w+') as f:
    f.write('um')
test()
os.remove(path_part)

print()
print('test 3: target file exists')
with open(path, 'w+') as f:
    f.write('um')
test()
print()
