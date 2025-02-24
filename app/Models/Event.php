<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Event extends Model
{
    use HasFactory;

    protected $fillable = [
        'title',
        'content',
        'file_id',
        'author_id',
        'edit_history'
    ];

    protected $casts = [
        'edit_history' => 'array'
    ];

    public function author(): BelongsTo
    {
        return $this->belongsTo(Member::class, 'author_id');
    }

    public function file(): BelongsTo
    {
        return $this->belongsTo(File::class);
    }
}
