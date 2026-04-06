
import pytest
import subprocess

@pytest.mark.parametrize(
  [
    "args",
    "input_",
  ],
  [
    pytest.param(
      ["-K", "123"],
      b""
    ),
    pytest.param(
      ["-K", "123"],
      b"123"
    ),
    pytest.param(
      ["-k", "0x123"],
      b""
    ),
    pytest.param(
      ["-k", "0x123"],
      b"123"
    ),
  ]
)
def test_app (
  executable:str, 
  args:list[str], 
  input_:bytes):
  p = subprocess.run(
    [executable, "-e"] + args,
    input=input_,
    stdout=subprocess.PIPE,
    text=False,
    shell=True,
    check=True,
  )
  encrypted_data = p.stdout
  p2 = subprocess.run(
    [executable, "-d"] + args,
    input=encrypted_data,
    stdout=subprocess.PIPE,
    text=False,
    shell=True,
    check=True,
  )
  assert p2.stdout[:len(input_)] == input_
