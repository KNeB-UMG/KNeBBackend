<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('events', function (Blueprint $table) {
            $table->id();
            $table->string('title');
            $table->text('content');
            $table->text('description')->nullable();
            $table->string('event_path')->unique();
            $table->boolean('visible')->default(false);
            $table->dateTime('event_date')->nullable();
            $table->foreignId('file_id')->nullable()->constrained('files')->onDelete('set null');
            $table->foreignId('author_id')->constrained('members');
            $table->json('edit_history')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
    }
};
