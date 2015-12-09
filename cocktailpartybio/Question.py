__author__ = 'Jani'
import itertools
import csv
import random

class Question:
    newid = itertools.count().next
    def __init__(self, q_text, a_1, a_2, a_3, a_4, c_a):

        self.id = Question.newid()
        self.q_text = q_text
        self.a_1 = a_1
        self.a_2 = a_2
        self.a_3 = a_3
        self.a_4 = a_4
        if (c_a == 1):
            self.correct = a_1
        elif (c_a == 2):
            self.correct = a_2
        elif (c_a == 3):
            self.correct = a_3
        else:
            self.correct = a_4

    def correct_answer(self, answer):
        if (answer == self.correct):
            return True
        return False

    def get_questiontext(self):
        return self.q_text

    def get_answerstext(self, i):
        if i == 1:
            return self.a_1
        elif i == 2:
            return self.a_2
        elif i == 3:
            return self.a_3
        elif i == 4:
            return self.a_4
        else:
            return 'no such answer'


class Test:

    def __init__(self, type):

        self.type = type
        infile = 'Questions/Questions' + str(type) + ".csv"
        count = 0
        with open(infile,"rb") as source:
            rdr = csv.reader( source )
            for j,r in enumerate(rdr):
                if j > 0:
                    count += 1
        print count
        questions = random.sample(range(1, count+1), 5)
        print questions
        Questions = []
        Answers = []
        with open(infile,"rb") as source:
            rdr = csv.reader( source )
            for j,r in enumerate(rdr):
                if j == 0:
                    firstline = r
                if j > 0 and j in questions:

                    Questions.append(Question(r[0], r[1], r[2], r[3], r[4], r[5]))
                    Answers.append(r[5])
        self.questions = Questions
        self.answers = Answers

    def get_questions(self):

        return self.questions

    def get_answers(self):

        return self.answers

    def answer_string(self):

        a_string = ''
        for A in self.answers:
            a_string += A
        return a_string


test = Test(2)