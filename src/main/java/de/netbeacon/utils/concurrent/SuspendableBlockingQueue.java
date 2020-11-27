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

package de.netbeacon.utils.concurrent;

import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class SuspendableBlockingQueue<E> {

    private final Queue<E> queue;
    private boolean isSuspended = false;

    public SuspendableBlockingQueue(){
        queue = new LinkedBlockingQueue<>();
    }

    public SuspendableBlockingQueue(int size){
        queue = new ArrayBlockingQueue<>(size);
    }

    public SuspendableBlockingQueue(BlockingQueue<E> queue){
        this.queue = queue;
    }

    public void suspend(boolean sus){
        synchronized (queue){
            isSuspended = sus;
            if(!isSuspended){
                queue.notifyAll();
            }
        }
    }

    public E get() throws InterruptedException {
        synchronized (queue) {
            while (isSuspended || queue.isEmpty()) {
                queue.wait();
            }
            return queue.poll();
        }
    }

    public void put(E elem) {
        synchronized (queue) {
            queue.offer(elem);
            if (!isSuspended) queue.notify();
        }
    }
}
