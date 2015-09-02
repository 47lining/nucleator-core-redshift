# Copyright 2015 47Lining LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

def djb2(source_string, size=16384):
    # Simple hash function to hash a string, based on Dan Bernstein's djb2
    # Input: source_string - a string that is to be hashed
    # Input: size - an integer (table size) for modular division
    
    # arbitrary large prime number to initialize
    hash = 3313

    # hash(i) = hash(i-1) * 33 + str[i]
    for char in source_string:
        hash = ((hash << 5) + hash) + ord(char)

    # Output: integer between 0 and size-1 (inclusive)
    return hash%size
