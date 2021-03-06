/*
 *     Copyright 2020 Horstexplorer @ https://www.netbeacon.de
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.netbeacon.utils.locks;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Can be used to simplify id based locking
 * @param <T>
 */
public class IdBasedLockHolder<T> {

    private final ReentrantReadWriteLock globalLock = new ReentrantReadWriteLock();
    private final ConcurrentHashMap<T, ReentrantLock> lockMap = new ConcurrentHashMap<>();

    public IdBasedLockHolder(){}

    /**
     * Returns the ReentrantLock matching the whole object
     *
     * @return ReentrantReadWriteLock
     */
    public ReentrantReadWriteLock getLock(){
        return globalLock;
    }

    /**
     * Returns the ReentrantLock matching to a given id
     *
     * @param t id object
     * @return ReentrantLock
     */
    public synchronized ReentrantLock getLock(T t){
        try{
            globalLock.readLock().lock(); // used to see if the object isnt locked globally
            if(!lockMap.containsKey(t)){
                lockMap.put(t, new ReentrantLock());
            }
            return lockMap.get(t);
        }finally {
            globalLock.readLock().lock();
        }
    }

    /**
     * Removes a lock from the pool
     * @param t id object
     */
    public void removeLock(T t){
        lockMap.remove(t);
    }
}
